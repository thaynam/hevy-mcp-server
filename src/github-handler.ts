/**
 * GitHub OAuth Handler
 * Handles OAuth authorization flow for multi-user authentication
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  getUpstreamAuthorizeUrl,
  fetchUpstreamAuthToken,
  fetchGitHubUser,
  type Props,
} from "./utils.js";
import {
  renderApprovalDialog,
  parseRedirectApproval,
  clientIdAlreadyApproved,
  storeClientApproval,
} from "./workers-oauth-utils.js";
import {
  getUserApiKey,
  setUserApiKey,
  deleteUserApiKey,
  maskApiKey,
} from "./lib/key-storage.js";
import { HevyClient } from "./lib/client.js";
import { constantTimeEqual, isValidLength } from "./lib/crypto-utils.js";
import { getCorsHeaders } from "./lib/cors.js";

// Zod schemas for input validation
const SaveKeyBodySchema = z.object({ apiKey: z.string().min(1).max(500) });
const TestKeyBodySchema = z.object({ apiKey: z.string().min(1).max(500) });
const TokenGrantTypeSchema = z.string().min(1).max(100);
const TokenCodeSchema = z.string().min(1).max(200);
const TokenClientIdSchema = z.string().min(1).max(200);
const TokenRedirectUriSchema = z.string().min(1).max(2000);
const TokenCodeVerifierSchema = z.string().max(200).optional();

interface Env {
  OAUTH_KV: KVNamespace;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  COOKIE_ENCRYPTION_KEY: string;
  ALLOWED_ORIGIN?: string;
}

// Create Hono app for OAuth routes
const app = new Hono<{ Bindings: Env }>();

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

const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60; // 1 year
const CSRF_COOKIE_NAME = "__Host-csrf_token";

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
  const useHostPrefix = name.startsWith("__Host-");
  return `${name}=${value}; Path=/; ${options.httpOnly ? "HttpOnly; " : ""}Secure; SameSite=Lax${useHostPrefix ? "" : ""}; Max-Age=${options.maxAge}`;
}

function appendSessionCookies(
  response: Response,
  sessionToken: string,
  csrfToken: string,
): void {
  response.headers.append(
    "Set-Cookie",
    buildCookie("__Host-session", sessionToken, {
      httpOnly: true,
      maxAge: SESSION_TTL_SECONDS,
    }),
  );
  response.headers.append(
    "Set-Cookie",
    buildCookie(CSRF_COOKIE_NAME, csrfToken, {
      httpOnly: false,
      maxAge: SESSION_TTL_SECONDS,
    }),
  );
}

function appendClearedAuthCookies(response: Response): void {
  response.headers.append(
    "Set-Cookie",
    buildCookie("__Host-session", "", { httpOnly: true, maxAge: 0 }),
  );
  response.headers.append(
    "Set-Cookie",
    buildCookie(CSRF_COOKIE_NAME, "", { httpOnly: false, maxAge: 0 }),
  );
}

function hasValidCsrf(c: any): boolean {
  const cookieToken = getCookie(c, CSRF_COOKIE_NAME);
  const headerToken = c.req.header("X-CSRF-Token");

  if (!cookieToken || !headerToken) {
    return false;
  }

  // Use constant-time comparison to prevent timing attacks
  return constantTimeEqual(cookieToken, headerToken);
}

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

// Add CORS middleware for all routes
app.use("*", async (c, next) => {
  // Handle OPTIONS preflight requests
  if (c.req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: { ...getCorsHeaders(c.env) },
    });
  }

  await next();

  // Add CORS headers to all responses
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

/**
 * Generate a random state parameter for OAuth
 */
function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

/**
 * Helper function to get the base URL for OAuth endpoints
 * Handles local development where Wrangler rewrites the Host header
 */
function getBaseUrl(c: any): string {
  const url = new URL(c.req.url);

  // Check for X-Forwarded-Host header (reverse proxy)
  const forwardedHost = c.req.header("X-Forwarded-Host");
  if (forwardedHost) {
    return `${url.protocol}//${forwardedHost}`;
  }

  // Check if request came from localhost (local dev)
  // Wrangler dev adds CF-Connecting-IP with localhost address
  const cfConnectingIp = c.req.header("CF-Connecting-IP");

  // Check if connecting from localhost (::1 is IPv6 localhost, 127.0.0.1 is IPv4)
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

/**
 * GET /.well-known/oauth-protected-resource
 * OAuth 2.0 Resource Server Metadata (RFC 8707)
 * Tells clients how to access the protected resource
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
 * Allows clients to discover OAuth configuration automatically
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
    token_endpoint_auth_methods_supported: ["none"], // Public client
    code_challenge_methods_supported: ["S256"], // PKCE support
    revocation_endpoint_auth_methods_supported: ["none"],
    service_documentation: `${baseUrl}/`,
  });

  response.headers.set(
    "Access-Control-Allow-Origin",
    getCorsHeaders(c.env)["Access-Control-Allow-Origin"],
  );
  return response;
});

/**
 * GET /authorize
 * OAuth authorization endpoint - initiates GitHub OAuth flow
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

  if (clientId === "setup") {
    const setupUrl = new URL(normalizedRedirectUri);
    if (setupUrl.pathname !== "/setup") {
      return c.text("Invalid redirect_uri for setup client", 400);
    }
  } else {
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

    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return c.text(
        "PKCE required: provide code_challenge and code_challenge_method=S256",
        400,
      );
    }
  }

  // Check if user is already authenticated (has session cookie)
  const sessionCookie = c.req.header("Cookie");
  const sessionToken = sessionCookie?.match(/__Host-session=([^;]+)/)?.[1];

  if (sessionToken) {
    // User is already authenticated, check if client is already approved
    const sessionData = await c.env.OAUTH_KV.get(
      `session:${sessionToken}`,
      "json",
    );

    if (
      sessionData &&
      typeof sessionData === "object" &&
      "login" in sessionData
    ) {
      const username = (sessionData as { login: string }).login;
      const alreadyApproved = await clientIdAlreadyApproved(
        c.env.OAUTH_KV,
        username,
        clientId,
      );

      if (alreadyApproved) {
        // Auto-approve and redirect
        const authCode = generateState();
        await c.env.OAUTH_KV.put(
          `authcode:${authCode}`,
          JSON.stringify({
            clientId,
            redirectUri: normalizedRedirectUri,
            codeChallenge,
            codeChallengeMethod,
            sessionToken,
          }),
          { expirationTtl: 600 }, // 10 minutes
        );

        const redirectUrl = new URL(normalizedRedirectUri);
        redirectUrl.searchParams.set("code", authCode);
        redirectUrl.searchParams.set("state", state);

        return c.redirect(redirectUrl.toString());
      }

      // Show approval dialog
      const html = renderApprovalDialog({
        clientId,
        redirectUri: normalizedRedirectUri,
        state,
        scope,
        ...(codeChallenge ? { codeChallenge } : {}),
        ...(codeChallengeMethod ? { codeChallengeMethod } : {}),
        userLogin: username,
        userName: (sessionData as { name?: string }).name || username,
        authorizeEndpoint: "/authorize",
      });

      return c.html(html);
    }
  }

  // User not authenticated, redirect to GitHub OAuth
  const githubState = generateState();

  // Store OAuth state and client info
  await c.env.OAUTH_KV.put(
    `oauth_state:${githubState}`,
    JSON.stringify({
      clientId,
      redirectUri: normalizedRedirectUri,
      state,
      scope,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || null,
    }),
    { expirationTtl: 600 }, // 10 minutes
  );

  const url = new URL(c.req.url);
  const callbackUri = `${url.protocol}//${url.host}/callback`;

  const githubAuthUrl = getUpstreamAuthorizeUrl(
    c.env.GITHUB_CLIENT_ID,
    callbackUri,
    githubState,
    "user:email",
  );

  return c.redirect(githubAuthUrl);
});

/**
 * POST /authorize
 * Handles approval form submission
 */
app.post("/authorize", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "authorize_post", 30, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const approval = await parseRedirectApproval(c.req.raw);

  if (!approval.approved) {
    return c.text("Authorization denied", 403);
  }

  // Get session from cookie
  const sessionCookie = c.req.header("Cookie");
  const sessionToken = sessionCookie?.match(/__Host-session=([^;]+)/)?.[1];

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
    !("login" in sessionData)
  ) {
    return c.text("Invalid session", 401);
  }

  const username = (sessionData as { login: string }).login;

  // Store approval
  await storeClientApproval(c.env.OAUTH_KV, username, approval.clientId);

  // Generate authorization code
  const authCode = generateState();
  await c.env.OAUTH_KV.put(
    `authcode:${authCode}`,
    JSON.stringify({
      clientId: approval.clientId,
      redirectUri: approval.redirectUri,
      codeChallenge: approval.codeChallenge || null,
      codeChallengeMethod: approval.codeChallengeMethod || null,
      sessionToken,
    }),
    { expirationTtl: 600 }, // 10 minutes
  );

  // Redirect back to client with auth code
  const redirectUrl = new URL(approval.redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  redirectUrl.searchParams.set("state", approval.state);

  return c.redirect(redirectUrl.toString());
});

/**
 * GET /callback
 * GitHub OAuth callback - exchanges code for access token
 */
app.get("/callback", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "callback", 30, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const code = c.req.query("code");
  const state = c.req.query("state");

  if (!code || !state) {
    return c.text("Missing code or state parameter", 400);
  }

  // Retrieve OAuth state
  const stateData = await c.env.OAUTH_KV.get(`oauth_state:${state}`, "json");
  if (!stateData || typeof stateData !== "object") {
    return c.html(
      `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorization Expired</title>
  <style>body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #333; } h1 { color: #c0392b; }</style>
</head>
<body>
  <h1>Authorization Request Expired</h1>
  <p>Your authorization request timed out after 10 minutes.</p>
  <p><strong>To continue:</strong> return to your MCP client and restart the connection. If you are using Claude Desktop, disconnect and reconnect the server.</p>
</body>
</html>`,
      400,
    );
  }

  const {
    clientId,
    redirectUri,
    state: clientState,
    scope,
    codeChallenge,
    codeChallengeMethod,
  } = stateData as {
    clientId: string;
    redirectUri: string;
    state: string;
    scope: string;
    codeChallenge?: string | null;
    codeChallengeMethod?: string | null;
  };

  try {
    // Exchange code for GitHub access token
    const url = new URL(c.req.url);
    const callbackUri = `${url.protocol}//${url.host}/callback`;

    const accessToken = await fetchUpstreamAuthToken(
      code,
      c.env.GITHUB_CLIENT_ID,
      c.env.GITHUB_CLIENT_SECRET,
      callbackUri,
    );

    // Fetch user information from GitHub
    const user = await fetchGitHubUser(accessToken);

    // Create session
    const sessionToken = generateState();
    const baseUrl = `${url.protocol}//${url.host}`;
    const sessionData: Props = {
      login: user.login,
      name: user.name,
      email: user.email,
      accessToken,
      baseUrl,
    };

    // Store session in KV (expires in 30 days)
    await c.env.OAUTH_KV.put(
      `session:${sessionToken}`,
      JSON.stringify(sessionData),
      {
        expirationTtl: SESSION_TTL_SECONDS,
      },
    );

    const csrfToken = generateState();

    // Clean up state
    await c.env.OAUTH_KV.delete(`oauth_state:${state}`);

    // Check if client is already approved
    const alreadyApproved = await clientIdAlreadyApproved(
      c.env.OAUTH_KV,
      user.login,
      clientId,
    );

    if (alreadyApproved) {
      // Auto-approve and redirect
      const authCode = generateState();
      await c.env.OAUTH_KV.put(
        `authcode:${authCode}`,
        JSON.stringify({
          clientId,
          redirectUri,
          codeChallenge: codeChallenge || null,
          codeChallengeMethod: codeChallengeMethod || null,
          sessionToken,
        }),
        { expirationTtl: 600 },
      );

      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set("code", authCode);
      redirectUrl.searchParams.set("state", clientState);

      // Set session cookie
      const response = c.redirect(redirectUrl.toString());
      appendSessionCookies(response, sessionToken, csrfToken);
      return response;
    }

    // Show approval dialog
    const html = renderApprovalDialog({
      clientId,
      redirectUri,
      state: clientState,
      scope,
      ...(codeChallenge ? { codeChallenge } : {}),
      ...(codeChallengeMethod ? { codeChallengeMethod } : {}),
      userLogin: user.login,
      userName: user.name,
      authorizeEndpoint: "/authorize",
    });

    const response = c.html(html);
    appendSessionCookies(response, sessionToken, csrfToken);
    return response;
  } catch (error) {
    const requestId = logError(c, "OAuth callback error", error);
    return c.text(
      `OAuth error. Please try again. Request ID: ${requestId}`,
      500,
    );
  }
});

/**
 * POST /token
 * OAuth 2.1 token endpoint - exchanges authorization code for access token
 * This is what MCP clients call to complete the OAuth flow
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
    const rawCode = formData.get("code") ?? undefined;
    const rawRedirectUri = formData.get("redirect_uri") ?? undefined;
    const rawClientId = formData.get("client_id") ?? undefined;
    const rawCodeVerifier = formData.get("code_verifier") ?? undefined;

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

    // Check grant_type
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

      const {
        sessionToken,
        clientId: storedClientId,
      } = refreshData as {
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

      // Refresh the session TTL so it doesn't expire while the refresh token is valid
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

    if (storedClientId !== "setup") {
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
      // Use constant-time comparison to prevent timing attacks
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

    // Retrieve session data
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

    // Generate independent OAuth access token
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
      {
        expirationTtl: SESSION_TTL_SECONDS,
      },
    );

    // Generate refresh token
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

    // Return OAuth 2.1 token response with refresh token
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

/**
 * POST /register
 * OAuth 2.1 dynamic client registration endpoint
 * For now, we accept all clients dynamically
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

    // Store client registration in KV (optional, for future validation)
    await c.env.OAUTH_KV.put(
      `client:${clientId}`,
      JSON.stringify({
        client_id: clientId,
        redirect_uris: normalizedRedirectUris,
        created_at: new Date().toISOString(),
      }),
      { expirationTtl: 365 * 24 * 60 * 60 }, // 1 year
    );

    // Return OAuth 2.1 registration response
    return c.json({
      client_id: clientId,
      redirect_uris: normalizedRedirectUris,
      grant_types: ["authorization_code"],
      token_endpoint_auth_method: "none", // Public client
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

/**
 * GET /logout
 * Deprecated route kept for compatibility
 */
app.get("/logout", (c) => {
  return c.text("Use POST /logout to log out securely.", 405);
});

/**
 * POST /logout
 * Clears user session and revokes issued access tokens
 */
app.post("/logout", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "logout", 30, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  if (!hasValidCsrf(c)) {
    return c.json({ error: "Invalid CSRF token" }, 403);
  }

  const sessionToken = getCookie(c, "__Host-session");

  if (sessionToken) {
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
  appendClearedAuthCookies(response);
  return response;
});

/**
 * Helper: Get authenticated session data
 */
async function getAuthenticatedSession(c: any): Promise<Props | null> {
  const sessionToken = getCookie(c, "__Host-session");

  if (!sessionToken) {
    return null;
  }

  const sessionData = await c.env.OAUTH_KV.get(
    `session:${sessionToken}`,
    "json",
  );
  if (
    !sessionData ||
    typeof sessionData !== "object" ||
    !("login" in sessionData)
  ) {
    return null;
  }

  return sessionData as Props;
}

/**
 * GET /setup
 * API key management page
 */
app.get("/setup", async (c) => {
  const session = await getAuthenticatedSession(c);

  if (!session) {
    // Redirect to login if not authenticated
    const url = new URL(c.req.url);
    const authorizeUrl = new URL("/authorize", url.origin);
    authorizeUrl.searchParams.set("client_id", "setup");
    authorizeUrl.searchParams.set("redirect_uri", `${url.origin}/setup`);
    authorizeUrl.searchParams.set("state", "setup");
    return c.redirect(authorizeUrl.toString());
  }

  // Check if user has an API key configured
  const hasApiKey = await getUserApiKey(
    c.env.OAUTH_KV,
    c.env.COOKIE_ENCRYPTION_KEY,
    session.login,
  );

  const safeUserName = escapeHtml(session.name || session.login);
  const safeUserLogin = escapeHtml(session.login);
  const csrfToken = getCookie(c, CSRF_COOKIE_NAME) || generateState();
  const safeCsrfToken = escapeHtml(csrfToken);

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Hevy API Key Setup</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

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
			max-width: 600px;
			width: 100%;
			padding: 40px;
		}

		h1 {
			color: #333;
			margin-bottom: 10px;
			font-size: 28px;
		}

		.user-info {
			background: #f8f9fa;
			padding: 15px;
			border-radius: 8px;
			margin-bottom: 30px;
			display: flex;
			align-items: center;
			gap: 12px;
		}

		.user-info img {
			width: 40px;
			height: 40px;
			border-radius: 50%;
		}

		.user-details {
			flex: 1;
		}

		.user-name {
			font-weight: 600;
			color: #333;
		}

		.user-login {
			font-size: 14px;
			color: #666;
		}

		.logout-btn {
			background: #dc3545;
			color: white;
			border: none;
			padding: 6px 12px;
			border-radius: 4px;
			font-size: 14px;
			cursor: pointer;
			text-decoration: none;
		}

		.logout-btn:hover {
			background: #c82333;
		}

		.status {
			padding: 15px;
			border-radius: 8px;
			margin-bottom: 20px;
			display: flex;
			align-items: center;
			gap: 10px;
		}

		.status.configured {
			background: #d4edda;
			color: #155724;
			border: 1px solid #c3e6cb;
		}

		.status.not-configured {
			background: #fff3cd;
			color: #856404;
			border: 1px solid #ffeaa7;
		}

		.status-icon {
			font-size: 24px;
		}

		label {
			display: block;
			font-weight: 600;
			margin-bottom: 8px;
			color: #333;
		}

		.help-text {
			font-size: 14px;
			color: #666;
			margin-bottom: 8px;
		}

		.help-text a {
			color: #667eea;
			text-decoration: none;
		}

		.help-text a:hover {
			text-decoration: underline;
		}

		input[type="text"] {
			width: 100%;
			padding: 12px;
			border: 2px solid #e0e0e0;
			border-radius: 6px;
			font-size: 14px;
			font-family: monospace;
			transition: border-color 0.2s;
		}

		input[type="text"]:focus {
			outline: none;
			border-color: #667eea;
		}

		.button-group {
			display: flex;
			gap: 10px;
			margin-top: 20px;
		}

		button {
			flex: 1;
			padding: 12px 24px;
			border: none;
			border-radius: 6px;
			font-size: 16px;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.2s;
		}

		.btn-primary {
			background: #667eea;
			color: white;
		}

		.btn-primary:hover:not(:disabled) {
			background: #5568d3;
		}

		.btn-secondary {
			background: #6c757d;
			color: white;
		}

		.btn-secondary:hover:not(:disabled) {
			background: #5a6268;
		}

		.btn-danger {
			background: #dc3545;
			color: white;
		}

		.btn-danger:hover:not(:disabled) {
			background: #c82333;
		}

		button:disabled {
			opacity: 0.6;
			cursor: not-allowed;
		}

		.message {
			padding: 12px;
			border-radius: 6px;
			margin-bottom: 20px;
			display: none;
		}

		.message.success {
			background: #d4edda;
			color: #155724;
			border: 1px solid #c3e6cb;
		}

		.message.error {
			background: #f8d7da;
			color: #721c24;
			border: 1px solid #f5c6cb;
		}

		.message.info {
			background: #d1ecf1;
			color: #0c5460;
			border: 1px solid #bee5eb;
		}

		.spinner {
			border: 3px solid #f3f3f3;
			border-top: 3px solid #667eea;
			border-radius: 50%;
			width: 20px;
			height: 20px;
			animation: spin 0.8s linear infinite;
			display: inline-block;
			margin-left: 10px;
		}

		@keyframes spin {
			0% { transform: rotate(0deg); }
			100% { transform: rotate(360deg); }
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🏋️ Hevy API Key Setup</h1>
		
		<div class="user-info">
			<div class="user-details">
				<div class="user-name">${safeUserName}</div>
				<div class="user-login">@${safeUserLogin}</div>
			</div>
			<button type="button" id="logoutBtn" class="logout-btn">Logout</button>
		</div>

		<div class="status ${hasApiKey ? "configured" : "not-configured"}">
			<span class="status-icon">${hasApiKey ? "✅" : "⚠️"}</span>
			<div>
				<strong>${hasApiKey ? "API Key Configured" : "API Key Not Configured"}</strong>
				<div style="font-size: 14px; margin-top: 4px;">
					${hasApiKey ? "Your Hevy API key is stored securely." : "Please enter your Hevy API key below to start using the MCP server."}
				</div>
			</div>
		</div>

		<div id="message" class="message"></div>

		<form id="apiKeyForm">
			<label for="apiKey">Hevy API Key</label>
			<div class="help-text">
				Get your API key from <a href="https://hevy.com/settings?developer" target="_blank" rel="noopener noreferrer">Hevy Settings → Developer</a>
			</div>
			<input 
				type="text" 
				id="apiKey" 
				name="apiKey" 
				placeholder="Enter your Hevy API key..."
				required
			/>

			<div class="button-group">
				<button type="button" id="testBtn" class="btn-secondary">Test Key</button>
				<button type="submit" class="btn-primary">Save Key</button>
			</div>
		</form>

		${
      hasApiKey
        ? `
		<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0;">
			<button id="deleteBtn" class="btn-danger" style="width: 100%;">Delete API Key</button>
		</div>
		`
        : ""
    }
	</div>

	<script>
		const csrfToken = '${safeCsrfToken}';
		const form = document.getElementById('apiKeyForm');
		const apiKeyInput = document.getElementById('apiKey');
		const testBtn = document.getElementById('testBtn');
		const deleteBtn = document.getElementById('deleteBtn');
		const logoutBtn = document.getElementById('logoutBtn');
		const message = document.getElementById('message');

		function showMessage(text, type) {
			message.textContent = text;
			message.className = 'message ' + type;
			message.style.display = 'block';
			setTimeout(() => {
				message.style.display = 'none';
			}, 5000);
		}

		async function testApiKey() {
			const apiKey = apiKeyInput.value.trim();
			if (!apiKey) {
				showMessage('Please enter an API key', 'error');
				return;
			}

			testBtn.disabled = true;
			testBtn.innerHTML = 'Testing...<span class="spinner"></span>';

			try {
				const response = await fetch('/api/test-key', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRF-Token': csrfToken,
					},
					body: JSON.stringify({ apiKey }),
				});

				const data = await response.json();

				if (response.ok) {
					showMessage('✅ API key is valid!', 'success');
				} else {
					showMessage('❌ ' + (data.error || 'Invalid API key'), 'error');
				}
			} catch (error) {
				showMessage('❌ Failed to test API key: ' + error.message, 'error');
			} finally {
				testBtn.disabled = false;
				testBtn.textContent = 'Test Key';
			}
		}

		async function saveApiKey(e) {
			e.preventDefault();

			const apiKey = apiKeyInput.value.trim();
			if (!apiKey) {
				showMessage('Please enter an API key', 'error');
				return;
			}

			const submitBtn = form.querySelector('button[type="submit"]');
			submitBtn.disabled = true;
			submitBtn.innerHTML = 'Saving...<span class="spinner"></span>';

			try {
				const response = await fetch('/api/save-key', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRF-Token': csrfToken,
					},
					body: JSON.stringify({ apiKey }),
				});

				const data = await response.json();

				if (response.ok) {
					showMessage('✅ API key saved successfully!', 'success');
					setTimeout(() => location.reload(), 1500);
				} else {
					showMessage('❌ ' + (data.error || 'Failed to save API key'), 'error');
				}
			} catch (error) {
				showMessage('❌ Failed to save API key: ' + error.message, 'error');
			} finally {
				submitBtn.disabled = false;
				submitBtn.textContent = 'Save Key';
			}
		}

		async function deleteApiKey() {
			if (!confirm('Are you sure you want to delete your API key? You will need to configure it again to use the MCP server.')) {
				return;
			}

			deleteBtn.disabled = true;
			deleteBtn.innerHTML = 'Deleting...<span class="spinner"></span>';

			try {
				const response = await fetch('/api/delete-key', {
					method: 'DELETE',
					headers: {
						'X-CSRF-Token': csrfToken,
					},
				});

				if (response.ok) {
					showMessage('✅ API key deleted successfully', 'success');
					setTimeout(() => location.reload(), 1500);
				} else {
					const data = await response.json();
					showMessage('❌ ' + (data.error || 'Failed to delete API key'), 'error');
				}
			} catch (error) {
				showMessage('❌ Failed to delete API key: ' + error.message, 'error');
			} finally {
				deleteBtn.disabled = false;
				deleteBtn.textContent = 'Delete API Key';
			}
		}

		async function logout() {
			logoutBtn.disabled = true;

			try {
				const response = await fetch('/logout', {
					method: 'POST',
					headers: {
						'X-CSRF-Token': csrfToken,
					},
				});

				if (response.ok) {
					location.href = '/';
				} else {
					showMessage('❌ Failed to log out', 'error');
				}
			} catch (error) {
				showMessage('❌ Failed to log out: ' + error.message, 'error');
			} finally {
				logoutBtn.disabled = false;
			}
		}

		testBtn.addEventListener('click', testApiKey);
		form.addEventListener('submit', saveApiKey);
		logoutBtn.addEventListener('click', logout);
		if (deleteBtn) {
			deleteBtn.addEventListener('click', deleteApiKey);
		}
	</script>
</body>
</html>
	`;

  const response = c.html(html);
  if (!getCookie(c, CSRF_COOKIE_NAME)) {
    response.headers.append(
      "Set-Cookie",
      buildCookie(CSRF_COOKIE_NAME, csrfToken, {
        httpOnly: false,
        maxAge: SESSION_TTL_SECONDS,
      }),
    );
  }

  return response;
});

/**
 * POST /api/test-key
 * Test if a Hevy API key is valid
 */
app.post("/api/test-key", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "api_test_key", 20, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const session = await getAuthenticatedSession(c);
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  if (!hasValidCsrf(c)) {
    return c.json({ error: "Invalid CSRF token" }, 403);
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { error: "invalid_json", message: "Request body must be valid JSON." },
      400,
    );
  }

  const parseResult = TestKeyBodySchema.safeParse(body);
  if (!parseResult.success) {
    return c.json(
      {
        error: "invalid_request",
        message:
          parseResult.error.issues[0]?.message ?? "Invalid request body.",
      },
      400,
    );
  }

  const { apiKey } = parseResult.data;

  try {
    // Test the API key by making a simple request
    const client = new HevyClient({ apiKey });
    await client.getWorkouts({ pageSize: 1 });

    return c.json({ valid: true });
  } catch (error) {
    const requestId = logError(c, "API key test error", error);
    return c.json(
      { error: "API key validation failed", request_id: requestId },
      400,
    );
  }
});

/**
 * POST /api/save-key
 * Save user's Hevy API key
 */
app.post("/api/save-key", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "api_save_key", 20, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const session = await getAuthenticatedSession(c);
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  if (!hasValidCsrf(c)) {
    return c.json({ error: "Invalid CSRF token" }, 403);
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { error: "invalid_json", message: "Request body must be valid JSON." },
      400,
    );
  }

  const parseResult = SaveKeyBodySchema.safeParse(body);
  if (!parseResult.success) {
    return c.json(
      {
        error: "invalid_request",
        message:
          parseResult.error.issues[0]?.message ?? "Invalid request body.",
      },
      400,
    );
  }

  const { apiKey } = parseResult.data;

  try {
    // Validate the API key first
    const client = new HevyClient({ apiKey });
    await client.getWorkouts({ pageSize: 1 });

    // Store encrypted API key in KV
    await setUserApiKey(
      c.env.OAUTH_KV,
      c.env.COOKIE_ENCRYPTION_KEY,
      session.login,
      apiKey,
    );

    return c.json({ success: true });
  } catch (error) {
    const requestId = logError(c, "API key save error", error);
    return c.json(
      { error: "Failed to save API key", request_id: requestId },
      400,
    );
  }
});

/**
 * GET /api/get-key
 * Get API key status
 */
app.get("/api/get-key", async (c) => {
  const session = await getAuthenticatedSession(c);
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    const apiKey = await getUserApiKey(
      c.env.OAUTH_KV,
      c.env.COOKIE_ENCRYPTION_KEY,
      session.login,
    );

    if (!apiKey) {
      return c.json({ configured: false });
    }

    return c.json({
      configured: true,
      maskedKey: maskApiKey(apiKey),
    });
  } catch (error) {
    logError(c, "API key retrieval error", error);
    return c.json({ error: "Failed to retrieve API key status" }, 500);
  }
});

/**
 * DELETE /api/delete-key
 * Delete user's API key
 */
app.delete("/api/delete-key", async (c) => {
  const rateLimitResponse = await checkRateLimit(c, "api_delete_key", 20, 60);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  const session = await getAuthenticatedSession(c);
  if (!session) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  if (!hasValidCsrf(c)) {
    return c.json({ error: "Invalid CSRF token" }, 403);
  }

  try {
    await deleteUserApiKey(c.env.OAUTH_KV, session.login);
    return c.json({ success: true });
  } catch (error) {
    logError(c, "API key deletion error", error);
    return c.json({ error: "Failed to delete API key" }, 500);
  }
});

export default app;
