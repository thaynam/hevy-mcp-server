import { createMiddleware } from "hono/factory";
import { decryptApiKey } from "../lib/key-storage.js";
import type { Props } from "../utils.js";

interface Env {
  OAUTH_KV: KVNamespace;
  COOKIE_ENCRYPTION_KEY: string;
}

interface Variables {
  props: Props;
}

// Bearer token format: exactly 64 lowercase hex characters
// (two concatenated generateState() outputs of 32 hex chars each)
const BEARER_TOKEN_REGEX = /^[0-9a-f]{64}$/;

/**
 * Bearer token authentication middleware
 * Validates Authorization header and stores user props in context
 */
export const bearerAuth = createMiddleware<{
  Bindings: Env;
  Variables: Variables;
}>(async (c, next) => {
  // Fast-path: FitCrew backend-to-server calls pass the Hevy API key directly
  // in X-Hevy-API-Key, bypassing the OAuth / KV lookup entirely.
  const hevyKey = c.req.header("X-Hevy-API-Key");
  if (hevyKey) {
    c.set("props", {
      hevyApiKey: hevyKey,
    });
    await next();
    return;
  }

  const authHeader = c.req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    const wwwAuthenticateValue = `Bearer realm="${c.req.url}", error="invalid_token"`;

    return c.json(
      {
        error: "unauthorized",
        message:
          "Authentication required. Please provide a valid Bearer token.",
      },
      401,
      {
        "WWW-Authenticate": wwwAuthenticateValue,
      },
    );
  }

  const token = authHeader.substring(7); // Remove "Bearer " prefix

  // Pre-validate token format before KV lookup to reject obviously invalid tokens
  if (!BEARER_TOKEN_REGEX.test(token)) {
    return c.json(
      { error: "unauthorized", message: "Invalid token format." },
      401,
    );
  }

  const accessTokenData = await c.env.OAUTH_KV.get(
    `access_token:${token}`,
    "json",
  );

  if (
    !accessTokenData ||
    typeof accessTokenData !== "object" ||
    !("sessionToken" in accessTokenData) ||
    typeof (accessTokenData as { sessionToken?: unknown }).sessionToken !==
      "string" ||
    !("issued_at" in accessTokenData) ||
    typeof (accessTokenData as { issued_at?: unknown }).issued_at !== "string"
  ) {
    return c.json(
      {
        error: "unauthorized",
        message: "Invalid token.",
      },
      401,
    );
  }

  const sessionToken = (
    accessTokenData as { sessionToken: string; issued_at: string }
  ).sessionToken;
  const issuedAt = (
    accessTokenData as { sessionToken: string; issued_at: string }
  ).issued_at;

  // Validate token hasn't exceeded max age (30 days)
  const tokenAge = Date.now() - new Date(issuedAt).getTime();
  const MAX_TOKEN_AGE_MS = 30 * 24 * 60 * 60 * 1000;
  if (tokenAge < 0 || tokenAge > MAX_TOKEN_AGE_MS) {
    return c.json({ error: "unauthorized", message: "Token expired." }, 401);
  }

  const sessionData = await c.env.OAUTH_KV.get(
    `session:${sessionToken}`,
    "json",
  );

  if (!sessionData || typeof sessionData !== "object") {
    return c.json(
      {
        error: "unauthorized",
        message: "Invalid token.",
      },
      401,
    );
  }

  const session = sessionData as { hevyApiKey: string; createdAt: string };

  if (!session.hevyApiKey) {
    return c.json(
      {
        error: "unauthorized",
        message: "Session missing API key.",
      },
      401,
    );
  }

  // Decrypt the API key from the session
  let hevyApiKey: string;
  try {
    hevyApiKey = await decryptApiKey(
      session.hevyApiKey,
      c.env.COOKIE_ENCRYPTION_KEY,
    );
  } catch {
    return c.json(
      {
        error: "unauthorized",
        message: "Failed to decrypt session data.",
      },
      401,
    );
  }

  // Store props in context variables
  c.set("props", {
    hevyApiKey,
    baseUrl: new URL(c.req.url).origin,
  });

  await next();
});
