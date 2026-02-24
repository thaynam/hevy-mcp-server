// Characterization test: documents CURRENT behavior as of Phase 1.
// STEST-03: CSRF protection edge cases.
//
// These tests pin the CSRF validation behavior of mutation endpoints so Phase 3
// module decomposition cannot introduce silent regressions.
//
// Test infrastructure: SELF.fetch() routes through the real Hono app via the
// Workers pool. No vi.mock() calls - uses real KV and real routing chain.

import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";

const TEST_SESSION_TOKEN = "test-session-token-csrf";
const TEST_CSRF_TOKEN = "test-csrf-token-value";

beforeEach(async () => {
  // Pre-populate a valid session so requests reach CSRF validation
  await env.OAUTH_KV.put(`session:${TEST_SESSION_TOKEN}`, JSON.stringify({
    login: "testuser",
    name: "Test User",
    email: "test@test.com",
    accessToken: "gh-token-fake",
    baseUrl: "https://example.com",
  }));
});

describe("STEST-03: CSRF protection - POST /api/save-key", () => {
  it("returns 403 when CSRF cookie and header are both missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // Request has a valid session but no CSRF cookie or X-CSRF-Token header.
    // hasValidCsrf() returns false -> 403 Forbidden.
    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}`,
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });

  it("returns 403 when CSRF cookie and header values do not match", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // constantTimeEqual(cookieToken, headerToken) returns false -> 403.
    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}; __Host-csrf_token=correct-token`,
        "X-CSRF-Token": "wrong-token",
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });

  it("returns 403 when CSRF cookie is present but X-CSRF-Token header is missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // hasValidCsrf: headerToken is undefined -> returns false -> 403.
    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}; __Host-csrf_token=${TEST_CSRF_TOKEN}`,
        // No X-CSRF-Token header
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });

  it("returns 403 when X-CSRF-Token header is present but CSRF cookie is missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // hasValidCsrf: cookieToken is undefined -> returns false -> 403.
    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}`,
        "X-CSRF-Token": TEST_CSRF_TOKEN,
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });

  it("returns 401 (not 403) when session cookie is missing entirely", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // Order of checks: getAuthenticatedSession() runs BEFORE hasValidCsrf().
    // No session -> 401 Unauthorized (never reaches CSRF check).
    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // No session, no CSRF
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    expect(response.status).toBe(401);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Unauthorized");
  });

  it("returns 4xx (not 500) when CSRF tokens have special characters but do not match", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection edge cases.
    // Special characters in tokens: mismatched -> 403.
    // constantTimeEqual is byte-level so special chars are fine as long as they match.
    const cookieToken = "token-abc123";
    const headerToken = "<script>alert(1)</script>";

    const response = await SELF.fetch("https://example.com/api/save-key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}; __Host-csrf_token=${cookieToken}`,
        "X-CSRF-Token": headerToken,
      },
      body: JSON.stringify({ apiKey: "test-key" }),
    });

    // Mismatched tokens -> 403
    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });
});

describe("STEST-03: CSRF protection - DELETE /api/delete-key", () => {
  it("returns 403 when CSRF cookie and header are both missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection applies consistently across all mutation endpoints.
    // Same missing-token test on /api/delete-key confirms uniform protection.
    const response = await SELF.fetch("https://example.com/api/delete-key", {
      method: "DELETE",
      headers: {
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}`,
      },
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });

  it("returns 403 when CSRF cookie and header values do not match", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-03: CSRF protection - mismatched tokens on delete endpoint.
    const response = await SELF.fetch("https://example.com/api/delete-key", {
      method: "DELETE",
      headers: {
        "Cookie": `__Host-session=${TEST_SESSION_TOKEN}; __Host-csrf_token=one-token`,
        "X-CSRF-Token": "different-token",
      },
    });

    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("Invalid CSRF token");
  });
});
