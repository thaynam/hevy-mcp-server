/**
 * OAuth Handler
 * Handles OAuth authorization flow with direct API key entry (no GitHub dependency).
 * Users enter their Hevy API key directly during the OAuth authorize step.
 */

import { Hono } from "hono";
import { z } from "zod";
import { encryptApiKey } from "./lib/key-storage.js";
import { HevyClient } from "./lib/client.js";
import { constantTimeEqual, isValidLength } from "./lib/crypto-utils.js";
import { getCorsHeaders } from "./lib/cors.js";

// --- Zod schemas for input validation ---
const TokenGrantTypeSchema = z.string().min(1).max(100);
const TokenCodeSchema = z.string().min(1).max(200);
const TokenClientIdSchema = z.string().min(1).max(200);
const TokenRedirectUriSchema = z.string().min(1).max(2000);
const TokenCodeVerifierSchema = z.string().max(200).optional();

// --- Env interface (no GitHub secrets) ---
interface Env {
	OAUTH_KV: KVNamespace;
	COOKIE_ENCRYPTION_KEY: string;
	ALLOWED_ORIGIN?: string;
}

// --- Constants ---
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const REFRESH_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60; // 1 year
const AUTH_CODE_TTL_SECONDS = 10 * 60; // 10 minutes

// --- Create Hono app ---
const app = new Hono<{ Bindings: Env }>();

// --- Helpers ---

function getRequestId(c: any): string {
	return c.req.header("CF-Ray") || crypto.randomUUID();
}

function logError(c: any, message: string, error: unknown): string {
	const requestId = getRequestId(c);
	console.error(`[${requestId}] ${message}`, error);
	return requestId;
}

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function isLocalhostHostname(hostname: string): boolean {
	return (
		hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1"
	);
}

function normalizeRedirectUri(rawUri: string): string | null {
	let parsed: URL;

	try {
		parsed = new URL(rawUri);
	} catch {
		return null;
	}

	if (parsed.username || parsed.password) {
		return null;
	}

	const isSecure = parsed.protocol === "https:";
	const isLocalHttp =
		parsed.protocol === "http:" && isLocalhostHostname(parsed.hostname);

	if (!isSecure && !isLocalHttp) {
		return null;
	}

	parsed.hash = "";
	return parsed.toString();
}

function toBase64Url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
}

async function createS256CodeChallenge(codeVerifier: string): Promise<string> {
	const encoded = new TextEncoder().encode(codeVerifier);
	const digest = await crypto.subtle.digest("SHA-256", encoded);
	return toBase64Url(new Uint8Array(digest));
}

/**
 * Generate a random hex state string (32 hex chars = 16 bytes)
 */
function generateState(): string {
	const array = new Uint8Array(16);
	crypto.getRandomValues(array);
	return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
		"",
	);
}

/**
 * Helper function to get the base URL for OAuth endpoints.
 * Handles local development where Wrangler rewrites the Host header.
 */
function getBaseUrl(c: any): string {
	const url = new URL(c.req.url);

	// Check for X-Forwarded-Host header (reverse proxy)
	const forwardedHost = c.req.header("X-Forwarded-Host");
	if (forwardedHost) {
		return `${url.protocol}//${forwardedHost}`;
	}

	// Check if request came from localhost (local dev)
	const cfConnectingIp = c.req.header("CF-Connecting-IP");
	const isLocalhost =
		cfConnectingIp === "::1" ||
		cfConnectingIp === "127.0.0.1" ||
		cfConnectingIp?.startsWith("127.");

	if (isLocalhost) {
		return `${url.protocol}//localhost:8787`;
	}

	// Production: use the Host header as-is
	return `${url.protocol}//${url.host}`;
}

function parseCookies(
	cookieHeader: string | undefined,
): Record<string, string> {
	if (!cookieHeader) {
		return {};
	}

	return cookieHeader
		.split(";")
		.map((part) => part.trim())
		.filter(Boolean)
		.reduce<Record<string, string>>((accumulator, entry) => {
			const separatorIndex = entry.indexOf("=");
			if (separatorIndex <= 0) {
				return accumulator;
			}

			const key = entry.slice(0, separatorIndex);
			const value = entry.slice(separatorIndex + 1);
			accumulator[key] = value;
			return accumulator;
		}, {});
}

function getCookie(c: any, key: string): string | undefined {
	const cookies = parseCookies(c.req.header("Cookie"));
	return cookies[key];
}

function buildCookie(
	name: string,
	value: string,
	options: { httpOnly: boolean; maxAge: number },
): string {
	return `${name}=${value}; Path=/; ${options.httpOnly ? "HttpOnly; " : ""}Secure; SameSite=Lax; Max-Age=${options.maxAge}`;
}

function appendSessionCookie(response: Response, sessionToken: string): void {
	response.headers.append(
		"Set-Cookie",
		buildCookie("__Host-session", sessionToken, {
			httpOnly: true,
			maxAge: SESSION_TTL_SECONDS,
		}),
	);
}

function appendClearedSessionCookie(response: Response): void {
	response.headers.append(
		"Set-Cookie",
		buildCookie("__Host-session", "", { httpOnly: true, maxAge: 0 }),
	);
}

/**
 * Rate limiting helper.
 * Returns a 429 Response if limit is exceeded, or null if the request is allowed.
 */
async function checkRateLimit(
	c: any,
	bucket: string,
	limit: number,
	windowSeconds: number,
): Promise<Response | null> {
	const clientIp = c.req.header("CF-Connecting-IP") || "unknown";
	const key = `rate_limit:${bucket}:${clientIp}`;
	const raw = await c.env.OAUTH_KV.get(key);
	const current = Number.parseInt(raw || "0", 10);

	if (!Number.isNaN(current) && current >= limit) {
		return c.json(
			{
				error: "rate_limited",
				message: "Too many requests. Please try again later.",
			},
			429,
			{
				"Retry-After": String(windowSeconds),
			},
		);
	}

	await c.env.OAUTH_KV.put(
		key,
		String(Number.isNaN(current) ? 1 : current + 1),
		{
			expirationTtl: windowSeconds,
		},
	);

	return null;
}

// --- Page styles (shared across authorize and consent pages) ---
const PAGE_STYLES = `
	* { margin: 0; padding: 0; box-sizing: border-box; }
	body {
		font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
		background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 20px;
	}
	.container {
		background: white;
		border-radius: 12px;
		box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
		max-width: 500px;
		width: 100%;
		padding: 40px;
	}
	h1 { color: #333; margin-bottom: 10px; font-size: 24px; }
	p { color: #555; margin-bottom: 20px; line-height: 1.5; }
	label { display: block; font-weight: 600; margin-bottom: 8px; color: #333; }
	.help {
		font-size: 14px;
		color: #666;
		margin-bottom: 8px;
	}
	.help a { color: #667eea; text-decoration: none; }
	.help a:hover { text-decoration: underline; }
	input[type="password"], input[type="text"] {
		width: 100%;
		padding: 12px;
		border: 2px solid #e0e0e0;
		border-radius: 6px;
		font-size: 14px;
		font-family: monospace;
		transition: border-color 0.2s;
		margin-bottom: 20px;
	}
	input:focus { outline: none; border-color: #667eea; }
	button {
		padding: 12px 24px;
		border: none;
		border-radius: 6px;
		font-size: 16px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
		width: 100%;
	}
	button:hover { opacity: 0.9; }
	.btn-primary { background: #667eea; color: white; }
	.btn-primary:hover { background: #5568d3; }
	.btn-allow { background: #28a745; color: white; margin-bottom: 10px; }
	.btn-allow:hover { background: #218838; }
	.btn-deny { background: #dc3545; color: white; }
	.btn-deny:hover { background: #c82333; }
	ul { margin: 0 0 20px 20px; color: #555; }
	ul li { margin-bottom: 6px; }
	.error-box {
		background: #f8d7da;
		color: #721c24;
		border: 1px solid #f5c6cb;
		padding: 12px;
		border-radius: 6px;
		margin-bottom: 20px;
		font-size: 14px;
	}
`;

// --- CORS middleware ---
app.use("*", async (c, next) => {
	if (c.req.method === "OPTIONS") {
		return new Response(null, {
			status: 204,
			headers: { ...getCorsHeaders(c.env) },
		});
	}

	await next();

	const corsHeaders = getCorsHeaders(c.env);
	c.res.headers.set(
		"Access-Control-Allow-Origin",
		corsHeaders["Access-Control-Allow-Origin"],
	);
	c.res.headers.set(
		"Access-Control-Allow-Methods",
		corsHeaders["Access-Control-Allow-Methods"],
	);
	c.res.headers.set(
		"Access-Control-Allow-Headers",
		corsHeaders["Access-Control-Allow-Headers"],
	);
});

// =============================================================================
// Well-known endpoints
// =============================================================================

/**
 * GET /.well-known/oauth-protected-resource
 * OAuth 2.0 Resource Server Metadata (RFC 8707)
 */
app.get("/.well-known/oauth-protected-resource", (c) => {
	const baseUrl = getBaseUrl(c);

	const response = c.json({
		resource: baseUrl,
		authorization_servers: [`${baseUrl}`],
		bearer_methods_supported: ["header"],
		resource_documentation: `${baseUrl}/`,
	});

	response.headers.set(
		"Access-Control-Allow-Origin",
		getCorsHeaders(c.env)["Access-Control-Allow-Origin"],
	);
	return response;
});

/**
 * GET /.well-known/oauth-authorization-server
 * OAuth 2.1 Authorization Server Metadata (RFC 8414)
 */
app.get("/.well-known/oauth-authorization-server", (c) => {
	const baseUrl = getBaseUrl(c);

	const response = c.json({
		issuer: baseUrl,
		authorization_endpoint: `${baseUrl}/authorize`,
		token_endpoint: `${baseUrl}/token`,
		registration_endpoint: `${baseUrl}/register`,
		scopes_supported: ["mcp"],
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		token_endpoint_auth_methods_supported: ["none"],
		code_challenge_methods_supported: ["S256"],
		revocation_endpoint_auth_methods_supported: ["none"],
		service_documentation: `${baseUrl}/`,
	});

	response.headers.set(
		"Access-Control-Allow-Origin",
		getCorsHeaders(c.env)["Access-Control-Allow-Origin"],
	);
	return response;
});

// =============================================================================
// GET /authorize
// =============================================================================

/**
 * GET /authorize
 * OAuth authorization endpoint.
 * If user has an existing session cookie with a valid API key, show consent page.
 * Otherwise, show the API key entry form.
 */
app.get("/authorize", async (c) => {
	const rateLimitResponse = await checkRateLimit(c, "authorize_get", 60, 60);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	const clientId = c.req.query("client_id");
	const redirectUri = c.req.query("redirect_uri");
	const state = c.req.query("state");
	const scope = c.req.query("scope") || "mcp";
	const codeChallenge = c.req.query("code_challenge");
	const codeChallengeMethod = c.req.query("code_challenge_method");

	if (!clientId || !redirectUri || !state) {
		return c.text(
			"Missing required parameters: client_id, redirect_uri, or state",
			400,
		);
	}

	// Validate input lengths
	if (
		!isValidLength(clientId, 200) ||
		!isValidLength(redirectUri, 2000) ||
		!isValidLength(state, 500)
	) {
		return c.text("Invalid parameter length", 400);
	}

	const normalizedRedirectUri = normalizeRedirectUri(redirectUri);
	if (!normalizedRedirectUri) {
		return c.text(
			"Invalid redirect_uri. Must be HTTPS (or localhost HTTP for development).",
			400,
		);
	}

	// Validate client registration
	const registeredClient = await c.env.OAUTH_KV.get(
		`client:${clientId}`,
		"json",
	);
	if (!registeredClient || typeof registeredClient !== "object") {
		return c.text("Unknown client_id", 400);
	}

	const redirectUris = (registeredClient as { redirect_uris?: string[] })
		.redirect_uris;
	if (
		!Array.isArray(redirectUris) ||
		!redirectUris.includes(normalizedRedirectUri)
	) {
		return c.text("redirect_uri is not registered for this client_id", 400);
	}

	// PKCE is required
	if (!codeChallenge || codeChallengeMethod !== "S256") {
		return c.text(
			"PKCE required: provide code_challenge and code_challenge_method=S256",
			400,
		);
	}

	// Build hidden field values for forms
	const oauthParams = {
		clientId,
		redirectUri: normalizedRedirectUri,
		state,
		scope,
		codeChallenge,
		codeChallengeMethod,
	};

	// Check for existing session cookie
	const sessionToken = getCookie(c, "__Host-session");

	if (sessionToken) {
		const sessionData = await c.env.OAUTH_KV.get(
			`session:${sessionToken}`,
			"json",
		);

		if (
			sessionData &&
			typeof sessionData === "object" &&
			"hevyApiKey" in sessionData
		) {
			// Session exists with API key - show consent page
			return c.html(renderConsentPage(oauthParams));
		}
	}

	// No valid session - show API key entry form
	return c.html(renderApiKeyEntryPage(oauthParams));
});

// =============================================================================
// POST /authorize
// =============================================================================

/**
 * POST /authorize
 * Handles three actions:
 *   - action=credentials : User submitted API key -> validate, create session, issue auth code
 *   - action=allow       : User consents (existing session) -> issue auth code
 *   - action=deny        : User denies -> redirect with error
 */
app.post("/authorize", async (c) => {
	const rateLimitResponse = await checkRateLimit(c, "authorize_post", 30, 60);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	let formData: FormData;
	try {
		formData = await c.req.formData();
	} catch {
		return c.text("Invalid form data", 400);
	}

	const action = formData.get("action") as string | null;
	const clientId = formData.get("client_id") as string | null;
	const redirectUri = formData.get("redirect_uri") as string | null;
	const state = formData.get("state") as string | null;
	const codeChallenge = formData.get("code_challenge") as string | null;
	const codeChallengeMethod = formData.get("code_challenge_method") as
		| string
		| null;

	if (!action || !clientId || !redirectUri || !state) {
		return c.text("Missing required form fields", 400);
	}

	const normalizedRedirectUri = normalizeRedirectUri(redirectUri);
	if (!normalizedRedirectUri) {
		return c.text("Invalid redirect_uri", 400);
	}

	// --- action=deny ---
	if (action === "deny") {
		const redirectUrl = new URL(normalizedRedirectUri);
		redirectUrl.searchParams.set("error", "access_denied");
		redirectUrl.searchParams.set(
			"error_description",
			"The user denied the authorization request",
		);
		redirectUrl.searchParams.set("state", state);
		return c.redirect(redirectUrl.toString());
	}

	// --- action=allow (existing session, user consents) ---
	if (action === "allow") {
		const sessionToken = getCookie(c, "__Host-session");
		if (!sessionToken) {
			return c.text("No session found", 401);
		}

		const sessionData = await c.env.OAUTH_KV.get(
			`session:${sessionToken}`,
			"json",
		);
		if (
			!sessionData ||
			typeof sessionData !== "object" ||
			!("hevyApiKey" in sessionData)
		) {
			return c.text("Invalid session", 401);
		}

		// Issue authorization code
		const authCode = generateState();
		await c.env.OAUTH_KV.put(
			`authcode:${authCode}`,
			JSON.stringify({
				clientId,
				redirectUri: normalizedRedirectUri,
				codeChallenge: codeChallenge || null,
				codeChallengeMethod: codeChallengeMethod || null,
				sessionToken,
			}),
			{ expirationTtl: AUTH_CODE_TTL_SECONDS },
		);

		const redirectUrl = new URL(normalizedRedirectUri);
		redirectUrl.searchParams.set("code", authCode);
		redirectUrl.searchParams.set("state", state);
		return c.redirect(redirectUrl.toString());
	}

	// --- action=credentials (user submitted API key) ---
	if (action === "credentials") {
		const hevyApiKey = (formData.get("hevy_api_key") as string | null)?.trim();

		if (!hevyApiKey || !isValidLength(hevyApiKey, 500)) {
			return c.html(
				renderApiKeyEntryPage(
					{
						clientId,
						redirectUri: normalizedRedirectUri,
						state,
						scope: (formData.get("scope") as string) || "mcp",
						codeChallenge: codeChallenge || "",
						codeChallengeMethod: codeChallengeMethod || "",
					},
					"Please enter a valid API key.",
				),
				400,
			);
		}

		// Validate the API key against Hevy API
		try {
			const client = new HevyClient({ apiKey: hevyApiKey });
			await client.getWorkouts({ pageSize: 1 });
		} catch (error) {
			logError(c, "API key validation failed", error);
			return c.html(
				renderApiKeyEntryPage(
					{
						clientId,
						redirectUri: normalizedRedirectUri,
						state,
						scope: (formData.get("scope") as string) || "mcp",
						codeChallenge: codeChallenge || "",
						codeChallengeMethod: codeChallengeMethod || "",
					},
					"Invalid API key. Please check your key and try again.",
				),
				400,
			);
		}

		// Encrypt and store in session
		const encryptedKey = await encryptApiKey(
			hevyApiKey,
			c.env.COOKIE_ENCRYPTION_KEY,
		);
		const sessionToken = `${generateState()}${generateState()}`;

		await c.env.OAUTH_KV.put(
			`session:${sessionToken}`,
			JSON.stringify({
				hevyApiKey: encryptedKey,
				createdAt: new Date().toISOString(),
			}),
			{ expirationTtl: SESSION_TTL_SECONDS },
		);

		// Issue authorization code
		const authCode = generateState();
		await c.env.OAUTH_KV.put(
			`authcode:${authCode}`,
			JSON.stringify({
				clientId,
				redirectUri: normalizedRedirectUri,
				codeChallenge: codeChallenge || null,
				codeChallengeMethod: codeChallengeMethod || null,
				sessionToken,
			}),
			{ expirationTtl: AUTH_CODE_TTL_SECONDS },
		);

		// Set session cookie and redirect with auth code
		const redirectUrl = new URL(normalizedRedirectUri);
		redirectUrl.searchParams.set("code", authCode);
		redirectUrl.searchParams.set("state", state);

		const response = c.redirect(redirectUrl.toString());
		appendSessionCookie(response, sessionToken);
		return response;
	}

	return c.text("Invalid action", 400);
});

// =============================================================================
// POST /token
// =============================================================================

/**
 * POST /token
 * OAuth 2.1 token endpoint.
 * Supports grant types: authorization_code and refresh_token.
 */
app.post("/token", async (c) => {
	const rateLimitResponse = await checkRateLimit(c, "token", 30, 60);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	let formData: FormData;
	try {
		formData = await c.req.formData();
	} catch {
		return c.json(
			{
				error: "invalid_request",
				error_description: "Request body must be valid form data.",
			},
			400,
		);
	}

	try {
		const rawGrantType = formData.get("grant_type") ?? undefined;

		const grantTypeResult = TokenGrantTypeSchema.safeParse(rawGrantType);
		if (!grantTypeResult.success) {
			return c.json(
				{
					error: "invalid_request",
					error_description:
						grantTypeResult.error.issues[0]?.message ?? "Invalid grant_type.",
				},
				400,
			);
		}

		const grantType = grantTypeResult.data;

		if (grantType !== "authorization_code" && grantType !== "refresh_token") {
			return c.json(
				{
					error: "unsupported_grant_type",
					error_description:
						"Supported grant types: authorization_code, refresh_token",
				},
				400,
			);
		}

		// --- Handle refresh_token grant ---
		if (grantType === "refresh_token") {
			const rawRefreshToken = formData.get("refresh_token") ?? undefined;
			const rawClientId = formData.get("client_id") ?? undefined;

			if (
				!rawRefreshToken ||
				typeof rawRefreshToken !== "string" ||
				!rawClientId ||
				typeof rawClientId !== "string"
			) {
				return c.json(
					{
						error: "invalid_request",
						error_description: "Missing refresh_token or client_id",
					},
					400,
				);
			}

			// Retrieve and consume refresh token (single-use / rotation)
			const kvKey = `refresh_token:${rawRefreshToken}`;
			const refreshData = await c.env.OAUTH_KV.get(kvKey, "json");
			if (!refreshData || typeof refreshData !== "object") {
				return c.json(
					{
						error: "invalid_grant",
						error_description: "Refresh token is invalid or expired",
					},
					400,
				);
			}

			const { sessionToken, clientId: storedClientId } = refreshData as {
				sessionToken: string;
				clientId: string;
			};

			if (storedClientId !== rawClientId) {
				return c.json(
					{
						error: "invalid_grant",
						error_description: "Client mismatch",
					},
					400,
				);
			}

			// Verify the session still exists
			const sessionData = await c.env.OAUTH_KV.get(
				`session:${sessionToken}`,
				"json",
			);
			if (!sessionData || typeof sessionData !== "object") {
				return c.json(
					{
						error: "invalid_grant",
						error_description: "Session expired",
					},
					400,
				);
			}

			// Delete old refresh token and its cross-reference (single-use)
			await c.env.OAUTH_KV.delete(kvKey);
			await c.env.OAUTH_KV.delete(
				`session_refresh_token:${sessionToken}:${rawRefreshToken}`,
			);

			// Refresh the session TTL
			await c.env.OAUTH_KV.put(
				`session:${sessionToken}`,
				JSON.stringify(sessionData),
				{ expirationTtl: SESSION_TTL_SECONDS },
			);

			// Generate new access token
			const accessToken = `${generateState()}${generateState()}`;
			await c.env.OAUTH_KV.put(
				`access_token:${accessToken}`,
				JSON.stringify({
					sessionToken,
					clientId: storedClientId,
					issued_at: new Date().toISOString(),
				}),
				{ expirationTtl: SESSION_TTL_SECONDS },
			);
			await c.env.OAUTH_KV.put(
				`session_access_token:${sessionToken}:${accessToken}`,
				"1",
				{ expirationTtl: SESSION_TTL_SECONDS },
			);

			// Issue new refresh token (rotation)
			const newRefreshToken = `${generateState()}${generateState()}`;
			await c.env.OAUTH_KV.put(
				`refresh_token:${newRefreshToken}`,
				JSON.stringify({
					sessionToken,
					clientId: storedClientId,
					created_at: new Date().toISOString(),
				}),
				{ expirationTtl: REFRESH_TOKEN_TTL_SECONDS },
			);
			await c.env.OAUTH_KV.put(
				`session_refresh_token:${sessionToken}:${newRefreshToken}`,
				"1",
				{ expirationTtl: REFRESH_TOKEN_TTL_SECONDS },
			);

			return c.json({
				access_token: accessToken,
				token_type: "Bearer",
				expires_in: SESSION_TTL_SECONDS,
				scope: "mcp",
				refresh_token: newRefreshToken,
			});
		}

		// --- Handle authorization_code grant ---
		const rawCode = formData.get("code") ?? undefined;
		const rawRedirectUri = formData.get("redirect_uri") ?? undefined;
		const rawClientId = formData.get("client_id") ?? undefined;
		const rawCodeVerifier = formData.get("code_verifier") ?? undefined;

		const codeResult = TokenCodeSchema.safeParse(rawCode);
		const redirectUriResult = TokenRedirectUriSchema.safeParse(rawRedirectUri);
		const clientIdResult = TokenClientIdSchema.safeParse(rawClientId);
		const codeVerifierResult =
			TokenCodeVerifierSchema.safeParse(rawCodeVerifier);

		if (
			!codeResult.success ||
			!redirectUriResult.success ||
			!clientIdResult.success ||
			!codeVerifierResult.success
		) {
			return c.json(
				{
					error: "invalid_request",
					error_description:
						"Missing or invalid required parameters: code, redirect_uri, or client_id",
				},
				400,
			);
		}

		const code = codeResult.data;
		const redirectUri = redirectUriResult.data;
		const clientId = clientIdResult.data;
		const codeVerifier = codeVerifierResult.data;

		const normalizedRedirectUri = normalizeRedirectUri(redirectUri);
		if (!normalizedRedirectUri) {
			return c.json(
				{
					error: "invalid_request",
					error_description: "Invalid redirect_uri",
				},
				400,
			);
		}

		// Retrieve authorization code from KV
		const authData = await c.env.OAUTH_KV.get(`authcode:${code}`, "json");
		if (!authData || typeof authData !== "object") {
			return c.json(
				{
					error: "invalid_grant",
					error_description: "Invalid or expired authorization code",
				},
				400,
			);
		}

		const {
			clientId: storedClientId,
			redirectUri: storedRedirectUri,
			sessionToken,
		} = authData as {
			clientId: string;
			redirectUri: string;
			codeChallenge?: string | null;
			codeChallengeMethod?: string | null;
			sessionToken: string;
		};

		// PKCE validation (always required)
		if (!codeVerifier || typeof codeVerifier !== "string") {
			return c.json(
				{
					error: "invalid_request",
					error_description: "Missing code_verifier",
				},
				400,
			);
		}

		const authCodeData = authData as {
			codeChallenge?: string | null;
			codeChallengeMethod?: string | null;
		};
		if (
			!authCodeData.codeChallenge ||
			authCodeData.codeChallengeMethod !== "S256"
		) {
			return c.json(
				{
					error: "invalid_grant",
					error_description: "Invalid PKCE parameters",
				},
				400,
			);
		}

		const computedCodeChallenge = await createS256CodeChallenge(codeVerifier);
		if (
			!constantTimeEqual(computedCodeChallenge, authCodeData.codeChallenge)
		) {
			return c.json(
				{
					error: "invalid_grant",
					error_description: "Invalid code_verifier",
				},
				400,
			);
		}

		// Validate client_id and redirect_uri match
		if (
			clientId !== storedClientId ||
			normalizedRedirectUri !== storedRedirectUri
		) {
			return c.json(
				{
					error: "invalid_grant",
					error_description: "Client ID or redirect URI mismatch",
				},
				400,
			);
		}

		// Verify session still exists
		const sessionData = await c.env.OAUTH_KV.get(
			`session:${sessionToken}`,
			"json",
		);
		if (!sessionData || typeof sessionData !== "object") {
			return c.json(
				{
					error: "invalid_grant",
					error_description: "Invalid or expired session",
				},
				400,
			);
		}

		// Delete the authorization code (single-use)
		await c.env.OAUTH_KV.delete(`authcode:${code}`);

		// Generate access token (64 hex chars)
		const accessToken = `${generateState()}${generateState()}`;
		await c.env.OAUTH_KV.put(
			`access_token:${accessToken}`,
			JSON.stringify({
				sessionToken,
				clientId: storedClientId,
				issued_at: new Date().toISOString(),
			}),
			{ expirationTtl: SESSION_TTL_SECONDS },
		);
		await c.env.OAUTH_KV.put(
			`session_access_token:${sessionToken}:${accessToken}`,
			"1",
			{ expirationTtl: SESSION_TTL_SECONDS },
		);

		// Generate refresh token (64 hex chars)
		const refreshToken = `${generateState()}${generateState()}`;
		await c.env.OAUTH_KV.put(
			`refresh_token:${refreshToken}`,
			JSON.stringify({
				sessionToken,
				clientId: storedClientId,
				created_at: new Date().toISOString(),
			}),
			{ expirationTtl: REFRESH_TOKEN_TTL_SECONDS },
		);
		await c.env.OAUTH_KV.put(
			`session_refresh_token:${sessionToken}:${refreshToken}`,
			"1",
			{ expirationTtl: REFRESH_TOKEN_TTL_SECONDS },
		);

		return c.json({
			access_token: accessToken,
			token_type: "Bearer",
			expires_in: SESSION_TTL_SECONDS,
			scope: "mcp",
			refresh_token: refreshToken,
		});
	} catch (error) {
		logError(c, "Token endpoint error", error);
		return c.json(
			{
				error: "server_error",
				error_description:
					"An error occurred while processing the token request",
			},
			500,
		);
	}
});

// =============================================================================
// POST /register
// =============================================================================

/**
 * POST /register
 * OAuth 2.1 dynamic client registration endpoint.
 * Public clients (no secret). Stores client data with redirect_uris.
 */
app.post("/register", async (c) => {
	const rateLimitResponse = await checkRateLimit(c, "register", 20, 60);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	try {
		const body = await c.req.json();
		const redirectUris = body.redirect_uris;

		if (
			!redirectUris ||
			!Array.isArray(redirectUris) ||
			redirectUris.length === 0
		) {
			return c.json(
				{
					error: "invalid_redirect_uri",
					error_description: "At least one redirect_uri is required",
				},
				400,
			);
		}

		const normalizedRedirectUris: string[] = [];
		for (const redirectUri of redirectUris) {
			if (typeof redirectUri !== "string") {
				return c.json(
					{
						error: "invalid_redirect_uri",
						error_description: "All redirect_uris must be strings",
					},
					400,
				);
			}

			const normalized = normalizeRedirectUri(redirectUri);
			if (!normalized) {
				return c.json(
					{
						error: "invalid_redirect_uri",
						error_description:
							"redirect_uris must be HTTPS (or localhost HTTP for development)",
					},
					400,
				);
			}

			normalizedRedirectUris.push(normalized);
		}

		// Generate a client ID
		const clientId = generateState();

		// Store client registration in KV
		await c.env.OAUTH_KV.put(
			`client:${clientId}`,
			JSON.stringify({
				client_id: clientId,
				redirect_uris: normalizedRedirectUris,
				created_at: new Date().toISOString(),
			}),
			{ expirationTtl: 365 * 24 * 60 * 60 }, // 1 year
		);

		return c.json({
			client_id: clientId,
			redirect_uris: normalizedRedirectUris,
			grant_types: ["authorization_code"],
			token_endpoint_auth_method: "none",
		});
	} catch (error) {
		logError(c, "Client registration error", error);
		return c.json(
			{
				error: "server_error",
				error_description: "An error occurred during client registration",
			},
			500,
		);
	}
});

// =============================================================================
// Logout endpoints
// =============================================================================

/**
 * GET /logout
 * Deprecated route kept for compatibility.
 */
app.get("/logout", (c) => {
	return c.text("Use POST /logout to log out securely.", 405);
});

/**
 * POST /logout
 * Clears user session and revokes all issued access and refresh tokens.
 */
app.post("/logout", async (c) => {
	const rateLimitResponse = await checkRateLimit(c, "logout", 30, 60);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	const sessionToken = getCookie(c, "__Host-session");

	if (sessionToken) {
		// Delete the session itself
		await c.env.OAUTH_KV.delete(`session:${sessionToken}`);

		// Revoke all access tokens for this session
		let cursor: string | undefined;
		do {
			const listResult = await c.env.OAUTH_KV.list({
				prefix: `session_access_token:${sessionToken}:`,
				...(cursor !== undefined ? { cursor } : {}),
			});

			for (const key of listResult.keys) {
				const accessToken = key.name.slice(
					`session_access_token:${sessionToken}:`.length,
				);
				await c.env.OAUTH_KV.delete(`access_token:${accessToken}`);
				await c.env.OAUTH_KV.delete(key.name);
			}

			cursor = listResult.list_complete ? undefined : listResult.cursor;
		} while (cursor);

		// Revoke all refresh tokens for this session
		let rtCursor: string | undefined;
		do {
			const listResult = await c.env.OAUTH_KV.list({
				prefix: `session_refresh_token:${sessionToken}:`,
				...(rtCursor !== undefined ? { cursor: rtCursor } : {}),
			});

			for (const key of listResult.keys) {
				const refreshToken = key.name.slice(
					`session_refresh_token:${sessionToken}:`.length,
				);
				await c.env.OAUTH_KV.delete(`refresh_token:${refreshToken}`);
				await c.env.OAUTH_KV.delete(key.name);
			}

			rtCursor = listResult.list_complete ? undefined : listResult.cursor;
		} while (rtCursor);
	}

	const response = c.text("Logged out successfully");
	appendClearedSessionCookie(response);
	return response;
});

// =============================================================================
// HTML rendering helpers
// =============================================================================

interface OAuthParams {
	clientId: string;
	redirectUri: string;
	state: string;
	scope: string;
	codeChallenge: string;
	codeChallengeMethod: string;
}

/**
 * Renders hidden form fields for OAuth parameters.
 */
function renderHiddenOAuthFields(params: OAuthParams): string {
	return `
		<input type="hidden" name="client_id" value="${escapeHtml(params.clientId)}">
		<input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
		<input type="hidden" name="state" value="${escapeHtml(params.state)}">
		<input type="hidden" name="scope" value="${escapeHtml(params.scope)}">
		<input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
		<input type="hidden" name="code_challenge_method" value="${escapeHtml(params.codeChallengeMethod)}">
	`;
}

/**
 * Renders the API key entry page (shown when no session exists).
 */
function renderApiKeyEntryPage(
	params: OAuthParams,
	errorMessage?: string,
): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Connect to Hevy</title>
	<style>${PAGE_STYLES}</style>
</head>
<body>
	<div class="container">
		<h1>Connect &amp; Authorize</h1>
		<p>Enter your Hevy API key to connect.</p>
		${errorMessage ? `<div class="error-box">${escapeHtml(errorMessage)}</div>` : ""}
		<form method="POST" action="/authorize">
			${renderHiddenOAuthFields(params)}
			<input type="hidden" name="action" value="credentials">
			<label for="hevy_api_key">Hevy API Key</label>
			<div class="help">Get your API key from <a href="https://hevy.com/settings?developer" target="_blank" rel="noopener noreferrer">Hevy Developer Settings</a></div>
			<input type="password" id="hevy_api_key" name="hevy_api_key" placeholder="Enter your Hevy API key..." required>
			<button type="submit" class="btn-primary">Connect &amp; Authorize</button>
		</form>
	</div>
</body>
</html>`;
}

/**
 * Renders the consent page (shown when session with API key already exists).
 */
function renderConsentPage(params: OAuthParams): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Authorize Access</title>
	<style>${PAGE_STYLES}</style>
</head>
<body>
	<div class="container">
		<h1>Authorize Access</h1>
		<p>An application wants to access your Hevy fitness data.</p>
		<p><strong>This application will be able to:</strong></p>
		<ul>
			<li>View your workouts and exercise history</li>
			<li>Create and update workouts</li>
			<li>View and manage routines</li>
			<li>View exercise templates</li>
		</ul>
		<form method="POST" action="/authorize">
			${renderHiddenOAuthFields(params)}
			<input type="hidden" name="action" value="allow">
			<button type="submit" class="btn-allow">Allow Access</button>
		</form>
		<form method="POST" action="/authorize">
			${renderHiddenOAuthFields(params)}
			<input type="hidden" name="action" value="deny">
			<button type="submit" class="btn-deny">Deny</button>
		</form>
	</div>
</body>
</html>`;
}

export default app;
