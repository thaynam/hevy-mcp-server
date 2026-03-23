import { Hono } from "hono";
import type { Props } from "./utils.js";
import oauthHandler from "./oauth-handler.js";
import { createMcpRoutes } from "./routes/mcp.js";
import utilityRoutes from "./routes/utility.js";
import { mcpHandlers } from "./mcp-handlers.js";
import { getCorsHeaders } from "./lib/cors.js";

// Environment interface for OAuth multi-user support
interface Env {
  MCP_OBJECT: DurableObjectNamespace;
  OAUTH_KV: KVNamespace;
  COOKIE_ENCRYPTION_KEY: string;
  ALLOWED_ORIGIN?: string;
}

// Variables interface for Hono context
interface Variables {
  props?: Props;
  session?: Props;
}

// Create main Hono app with proper TypeScript types
const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Global CORS middleware
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

  // Add security headers
  c.res.headers.set("X-Content-Type-Options", "nosniff");
  c.res.headers.set("X-Frame-Options", "DENY");
  c.res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  c.res.headers.set(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  c.res.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'",
  );
});

// Error handling middleware
app.onError((err, c) => {
  const requestId = c.req.header("CF-Ray") || crypto.randomUUID();
  console.error(`[${requestId}] Unhandled error:`, err);
  return c.json(
    {
      error: "internal_server_error",
      message: "An unexpected error occurred",
      request_id: requestId,
    },
    500,
  );
});

// Mount routes (order matters!)
app.route("/", oauthHandler); // OAuth routes (highest priority)
app.route("/", createMcpRoutes(mcpHandlers)); // MCP endpoints
app.route("/", utilityRoutes); // Health, home, etc.

// 404 handler
app.notFound((c) => {
  return c.text("Not found", 404);
});

export default app;
export type { Env, Variables };
