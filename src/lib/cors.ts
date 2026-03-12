/**
 * Returns CORS headers, reading ALLOWED_ORIGIN from the Worker env.
 * Falls back to "*" for local dev (when ALLOWED_ORIGIN is not set).
 * X-Hevy-API-Key is included so CORS preflight passes for FitCrew backend calls.
 */
export function getCorsHeaders(env: { ALLOWED_ORIGIN?: string }) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN ?? "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Hevy-API-Key",
    "Access-Control-Max-Age": "86400",
  };
}
