import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock key-storage so we don't need real AES-GCM encryption in tests
vi.mock("../../src/lib/key-storage.js", () => ({
  decryptApiKey: vi.fn().mockResolvedValue("decrypted-hevy-api-key"),
}));

import { bearerAuth } from "../../src/middleware/auth.js";
import { decryptApiKey } from "../../src/lib/key-storage.js";

// Mock the KV namespace
const mockKV = {
  get: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
};

// Valid 64 hex-char access tokens (matching the BEARER_TOKEN_REGEX format)
// These are two concatenated 32-hex-char generateState() outputs
const VALID_TOKEN_A =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const VALID_TOKEN_B =
  "deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234";
const VALID_TOKEN_C =
  "0000000000000000000000000000000000000000000000000000000000000001";
const VALID_TOKEN_D =
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const TEST_ENCRYPTION_KEY = "a".repeat(64); // 64 hex chars for AES-256

describe("Bearer Auth Middleware", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset the mock to default behavior
    (decryptApiKey as ReturnType<typeof vi.fn>).mockResolvedValue("decrypted-hevy-api-key");
  });

  function createMockContext(request: Request) {
    return {
      req: {
        header: (name: string) => request.headers.get(name),
        url: request.url,
      },
      env: { OAUTH_KV: mockKV, COOKIE_ENCRYPTION_KEY: TEST_ENCRYPTION_KEY },
      set: vi.fn(),
      json: vi.fn().mockReturnValue(new Response()),
    };
  }

  it("should pass through with valid access token mapped to a valid session", async () => {
    // Session now stores { hevyApiKey: encryptedString, createdAt: string }
    const mockSession = {
      hevyApiKey: "encrypted-api-key-base64",
      createdAt: new Date().toISOString(),
    };

    mockKV.get
      .mockResolvedValueOnce({
        sessionToken: "session-123",
        issued_at: new Date(Date.now() - 1000).toISOString(),
      })
      .mockResolvedValueOnce(mockSession);

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_A}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockKV.get).toHaveBeenNthCalledWith(
      1,
      `access_token:${VALID_TOKEN_A}`,
      "json",
    );
    expect(mockKV.get).toHaveBeenNthCalledWith(
      2,
      "session:session-123",
      "json",
    );
    // decryptApiKey should have been called with the encrypted key and encryption key
    expect(decryptApiKey).toHaveBeenCalledWith(
      "encrypted-api-key-base64",
      TEST_ENCRYPTION_KEY,
    );
    // Props should match new shape: { hevyApiKey, baseUrl }
    expect(mockContext.set).toHaveBeenCalledWith("props", {
      hevyApiKey: "decrypted-hevy-api-key",
      baseUrl: "http://localhost",
    });
    expect(next).toHaveBeenCalled();
  });

  it("should return 401 for missing Authorization header", async () => {
    const request = new Request("http://localhost/mcp", {
      method: "POST",
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message:
          "Authentication required. Please provide a valid Bearer token.",
      },
      401,
      {
        "WWW-Authenticate": `Bearer realm="${request.url}", error="invalid_token"`,
      },
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should return 401 for token not found in access token store", async () => {
    mockKV.get.mockResolvedValueOnce(null);

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_B}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockKV.get).toHaveBeenCalledWith(
      `access_token:${VALID_TOKEN_B}`,
      "json",
    );
    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message: "Invalid token.",
      },
      401,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should return 401 for token with invalid format (not 64 hex chars)", async () => {
    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer invalid-token-format" },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    // KV should NOT be queried for format-invalid tokens
    expect(mockKV.get).not.toHaveBeenCalled();
    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message: "Invalid token format.",
      },
      401,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should return 401 when mapped session is missing", async () => {
    mockKV.get
      .mockResolvedValueOnce({
        sessionToken: "expired-session",
        issued_at: new Date(Date.now() - 1000).toISOString(),
      })
      .mockResolvedValueOnce(null);

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_C}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockKV.get).toHaveBeenNthCalledWith(
      1,
      `access_token:${VALID_TOKEN_C}`,
      "json",
    );
    expect(mockKV.get).toHaveBeenNthCalledWith(
      2,
      "session:expired-session",
      "json",
    );
    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message: "Invalid token.",
      },
      401,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should return 401 when session is missing hevyApiKey", async () => {
    mockKV.get
      .mockResolvedValueOnce({
        sessionToken: "session-no-key",
        issued_at: new Date(Date.now() - 1000).toISOString(),
      })
      .mockResolvedValueOnce({
        createdAt: new Date().toISOString(),
        // hevyApiKey is missing
      });

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_C}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message: "Session missing API key.",
      },
      401,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should return 401 when decryption fails", async () => {
    (decryptApiKey as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Decryption failed"),
    );

    mockKV.get
      .mockResolvedValueOnce({
        sessionToken: "session-bad-decrypt",
        issued_at: new Date(Date.now() - 1000).toISOString(),
      })
      .mockResolvedValueOnce({
        hevyApiKey: "corrupted-encrypted-data",
        createdAt: new Date().toISOString(),
      });

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_C}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message: "Failed to decrypt session data.",
      },
      401,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("should handle KV storage errors", async () => {
    // Provide valid initial data, error happens on session lookup
    mockKV.get
      .mockResolvedValueOnce({
        sessionToken: "session-123",
        issued_at: new Date().toISOString(),
      })
      .mockRejectedValueOnce(new Error("KV storage error"));

    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: `Bearer ${VALID_TOKEN_D}` },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await expect(bearerAuth(mockContext as any, next)).rejects.toThrow(
      "KV storage error",
    );
  });

  it("should include WWW-Authenticate header for malformed bearer header", async () => {
    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer" },
    });

    const mockContext = createMockContext(request);
    const next = vi.fn();

    await bearerAuth(mockContext as any, next);

    expect(mockContext.json).toHaveBeenCalledWith(
      {
        error: "unauthorized",
        message:
          "Authentication required. Please provide a valid Bearer token.",
      },
      401,
      {
        "WWW-Authenticate": `Bearer realm="${request.url}", error="invalid_token"`,
      },
    );
  });

  describe("X-Hevy-API-Key header auth fast-path", () => {
    it("should bypass KV lookup and set props.hevyApiKey when header is present", async () => {
      const request = new Request("http://localhost/mcp", {
        method: "POST",
        headers: { "X-Hevy-API-Key": "test-athlete-hevy-key-123" },
      });

      const mockContext = createMockContext(request);
      const next = vi.fn();

      await bearerAuth(mockContext as any, next);

      // KV should NOT be called -- we bypassed it
      expect(mockKV.get).not.toHaveBeenCalled();

      // Props should carry the key directly (new shape, no login/name/email)
      expect(mockContext.set).toHaveBeenCalledWith("props", {
        hevyApiKey: "test-athlete-hevy-key-123",
      });

      // next() must be called so the request proceeds
      expect(next).toHaveBeenCalled();
    });

    it("should fall through to Bearer validation when X-Hevy-API-Key is absent", async () => {
      // No X-Hevy-API-Key header -- should hit normal Bearer validation
      const request = new Request("http://localhost/mcp", {
        method: "POST",
        // No X-Hevy-API-Key -- no Authorization either -> should return 401
      });

      const mockContext = createMockContext(request);
      const next = vi.fn();

      await bearerAuth(mockContext as any, next);

      // next() should NOT be called (unauthenticated)
      expect(next).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "unauthorized" }),
        401,
        expect.anything(),
      );
    });
  }); // end of nested describe "X-Hevy-API-Key header auth fast-path"
}); // end of outer describe "Bearer Auth Middleware"
