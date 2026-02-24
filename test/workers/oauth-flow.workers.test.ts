// Characterization test: documents CURRENT behavior as of Phase 1.
// STEST-04: OAuth flow error paths (expired state, mismatched redirect_uri, state tampering)
// STEST-05: Concurrent authorization (race condition documented as known limitation)
// STEST-06: Authorization code double-use (consumed code returns 400 invalid_grant)
//
// Tests run in Workers pool via SELF.fetch() through the real Hono app routing chain.
// No vi.mock() calls - uses real KV and real routing.

import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// STEST-04: GET /callback error paths
// ---------------------------------------------------------------------------

describe("STEST-04: GET /callback - missing or invalid parameters", () => {
  it("returns 400 when both code and state are missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-04: OAuth flow error paths.
    // github-handler.ts line 499-501: returns 400 "Missing code or state parameter".
    const response = await SELF.fetch("https://example.com/callback");

    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("Missing code or state parameter");
  });

  it("returns 400 when code is present but state is missing", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-04: OAuth flow error paths.
    // state is undefined -> 400 "Missing code or state parameter".
    const response = await SELF.fetch("https://example.com/callback?code=abc");

    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("Missing code or state parameter");
  });

  it("returns 400 for state that was never stored (tampering / unknown state)", async () => {
    // Characterization test: updated in Phase 2 (ERRH-01).
    // STEST-04: OAuth flow error paths.
    // github-handler.ts: KV lookup returns null -> 400 HTML "Authorization Expired" page.
    // Updated from plain text to HTML error page in Phase 2 (ERRH-01).
    const response = await SELF.fetch("https://example.com/callback?code=abc&state=never-stored-state");

    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("Authorization Expired");
    expect(text).toContain("Authorization Request Expired");
  });

  it("returns 400 for expired state (deleted from KV to simulate TTL expiry)", async () => {
    // Characterization test: updated in Phase 2 (ERRH-01).
    // STEST-04: OAuth flow error paths.
    // Pitfall P4: fake timers do NOT control KV TTL. Instead, delete the key to simulate expiry.
    // github-handler.ts: KV lookup returns null -> 400 HTML "Authorization Expired" page.
    // Updated from plain text to HTML error page in Phase 2 (ERRH-01).
    const state = "test-expired-state";
    await env.OAUTH_KV.put(`oauth_state:${state}`, JSON.stringify({
      clientId: "test-client",
      redirectUri: "https://example.com/callback",
      state: "client-state",
      scope: "mcp",
    }));
    // Simulate TTL expiry by deleting the key
    await env.OAUTH_KV.delete(`oauth_state:${state}`);

    const response = await SELF.fetch(`https://example.com/callback?code=abc&state=${state}`);

    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("Authorization Expired");
    expect(text).toContain("Authorization Request Expired");
  });
});

describe("STEST-04: GET /callback - GitHub exchange failures (KNOWN BUG)", () => {
  it("returns 500 when state is valid but GitHub code exchange fails (no real GitHub)", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-04: OAuth flow error paths.
    // KNOWN BUG: returns 500 (unhandled exception in catch block); should return a user-readable error.
    // Fix tracked in ERRH-01 (Phase 2).
    //
    // github-handler.ts line 523: fetchUpstreamAuthToken calls GitHub API.
    // In Workers pool tests there is no real GitHub -> throws -> catch at line 598-601 returns 500.
    const state = "test-valid-state-github-fail";
    await env.OAUTH_KV.put(`oauth_state:${state}`, JSON.stringify({
      clientId: "setup",
      redirectUri: "https://example.com/setup",
      state: "client-state",
      scope: "mcp",
      codeChallenge: null,
      codeChallengeMethod: null,
    }));

    const response = await SELF.fetch(`https://example.com/callback?code=fake-code&state=${state}`);

    // KNOWN BUG: returns 500 (unhandled exception in catch block); should return a user-readable error.
    // Fix tracked in ERRH-01 (Phase 2).
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).toContain("OAuth error");
  });
});

// ---------------------------------------------------------------------------
// STEST-05: Concurrent authorization (race condition documented as known limitation)
// ---------------------------------------------------------------------------

describe("STEST-05: GET /callback - concurrent authorization attempts", () => {
  it("documents concurrent callback behavior as known limitation", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-05: Concurrent authorization.
    //
    // NOTE: In the Workers pool, concurrent requests against the same KV
    // data do not have transactional guarantees. This test documents
    // the current behavior, which may include race conditions.
    //
    // Both requests will fail at the GitHub code exchange step (no real GitHub)
    // and fall into the catch block returning 500.
    // KNOWN BUG: callback catch block returns 500 for GitHub API failures. Fix tracked in ERRH-01.
    const state = "test-concurrent-state";
    await env.OAUTH_KV.put(`oauth_state:${state}`, JSON.stringify({
      clientId: "setup",
      redirectUri: "https://example.com/setup",
      state: "client-state",
      scope: "mcp",
      codeChallenge: null,
      codeChallengeMethod: null,
    }));

    // Send two concurrent requests for the same state
    const [response1, response2] = await Promise.all([
      SELF.fetch(`https://example.com/callback?code=fake-code-1&state=${state}`),
      SELF.fetch(`https://example.com/callback?code=fake-code-2&state=${state}`),
    ]);

    // KNOWN BUG: both return 500 (unhandled exception in catch block due to GitHub API failure).
    // Fix tracked in ERRH-01 (Phase 2).
    // Known limitation: no transactional guarantee on KV state deletion under concurrency.
    expect(response1.status).toBe(500);
    expect(response2.status).toBe(500);
    const text1 = await response1.text();
    const text2 = await response2.text();
    expect(text1).toContain("OAuth error");
    expect(text2).toContain("OAuth error");
  });
});

// ---------------------------------------------------------------------------
// STEST-04: POST /token error paths
// ---------------------------------------------------------------------------

describe("STEST-04: POST /token - mismatched redirect_uri", () => {
  it("returns 400 when redirect_uri does not match stored value", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-04: OAuth flow error paths.
    // github-handler.ts line 720: clientId or redirectUri mismatch -> 400 "Client ID or redirect URI mismatch".
    const testCode = "test-code-redirect-mismatch";
    const sessionToken = "test-session-redirect";
    await env.OAUTH_KV.put(`session:${sessionToken}`, JSON.stringify({
      login: "testuser", name: "Test", email: "t@t.com",
      accessToken: "gh-token", baseUrl: "https://example.com",
    }));
    await env.OAUTH_KV.put(`authcode:${testCode}`, JSON.stringify({
      clientId: "setup",
      redirectUri: "https://good.com/callback",
      sessionToken,
    }), { expirationTtl: 600 });

    const formData = new URLSearchParams({
      grant_type: "authorization_code",
      code: testCode,
      redirect_uri: "https://evil.com/callback",
      client_id: "setup",
    });

    const response = await SELF.fetch("https://example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData.toString(),
    });

    expect(response.status).toBe(400);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toContain("mismatch");
  });
});

// ---------------------------------------------------------------------------
// STEST-06: Authorization code double-use
// ---------------------------------------------------------------------------

describe("STEST-06: POST /token - authorization code double-use", () => {
  it("first call succeeds, second call returns 400 invalid_grant", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-06: Authorization code double-use.
    // github-handler.ts line 743: authcode deleted after first use (single-use enforcement).
    // Second call: line 665-674 -> authData is null -> 400 "invalid_grant".
    const testCode = "test-code-double-use";
    const sessionToken = "test-session-double";
    await env.OAUTH_KV.put(`session:${sessionToken}`, JSON.stringify({
      login: "testuser", name: "Test", email: "t@t.com",
      accessToken: "gh-token", baseUrl: "https://example.com",
    }));
    await env.OAUTH_KV.put(`authcode:${testCode}`, JSON.stringify({
      clientId: "setup",
      redirectUri: "https://localhost/callback",
      sessionToken,
    }), { expirationTtl: 600 });

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: testCode,
      redirect_uri: "https://localhost/callback",
      client_id: "setup",
    });

    // First call: consumes the code, should succeed (200 with access_token)
    const first = await SELF.fetch("https://example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    expect(first.status).toBe(200);
    const firstBody = await first.json() as Record<string, unknown>;
    expect(firstBody.access_token).toBeTruthy();
    expect(firstBody.token_type).toBe("Bearer");

    // Second call: code already consumed from KV -> 400 invalid_grant
    const second = await SELF.fetch("https://example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    expect(second.status).toBe(400);
    const secondBody = await second.json() as Record<string, unknown>;
    expect(secondBody.error).toBe("invalid_grant");
  });

  it("returns 400 unsupported_grant_type for client_credentials grant", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-06: Authorization code double-use.
    // github-handler.ts line 623: grantType !== "authorization_code" -> 400 "unsupported_grant_type".
    const formData = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: "setup",
    });

    const response = await SELF.fetch("https://example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData.toString(),
    });

    expect(response.status).toBe(400);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("unsupported_grant_type");
  });

  it("returns 400 invalid_grant when authorization code does not exist in KV", async () => {
    // Characterization test: documents CURRENT behavior as of Phase 1.
    // STEST-06: Authorization code double-use.
    // github-handler.ts line 665-674: authData null -> 400 invalid_grant.
    // Also covers the case where a code is consumed and then reused.
    const formData = new URLSearchParams({
      grant_type: "authorization_code",
      code: "nonexistent-code-xyz",
      redirect_uri: "https://localhost/callback",
      client_id: "setup",
    });

    const response = await SELF.fetch("https://example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData.toString(),
    });

    expect(response.status).toBe(400);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
  });
});
