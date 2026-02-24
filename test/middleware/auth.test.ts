import { describe, it, expect, beforeEach, vi } from "vitest";
import { bearerAuth } from "../../src/middleware/auth.js";

// Mock the KV namespace
const mockKV = {
	get: vi.fn(),
	put: vi.fn(),
	delete: vi.fn(),
};

// Valid 64 hex-char access tokens (matching the BEARER_TOKEN_REGEX format)
// These are two concatenated 32-hex-char generateState() outputs
const VALID_TOKEN_A = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const VALID_TOKEN_B = "deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234";
const VALID_TOKEN_C = "0000000000000000000000000000000000000000000000000000000000000001";
const VALID_TOKEN_D = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

describe("Bearer Auth Middleware", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	function createMockContext(request: Request) {
		return {
			req: {
				header: (name: string) => request.headers.get(name),
				url: request.url,
			},
			env: { OAUTH_KV: mockKV },
			set: vi.fn(),
			json: vi.fn().mockReturnValue(new Response()),
		};
	}

	it("should pass through with valid access token mapped to a valid session", async () => {
		const mockProps = {
			login: "testuser",
			baseUrl: "http://localhost",
			accessToken: "github-access-token",
		};

		mockKV.get
			.mockResolvedValueOnce({
				sessionToken: "session-123",
				issued_at: new Date(Date.now() - 1000).toISOString(),
				clientId: "test-client",
			})
			.mockResolvedValueOnce(mockProps);

		const request = new Request("http://localhost/mcp", {
			method: "POST",
			headers: { "Authorization": `Bearer ${VALID_TOKEN_A}` },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenNthCalledWith(1, `access_token:${VALID_TOKEN_A}`, "json");
		expect(mockKV.get).toHaveBeenNthCalledWith(2, "session:session-123", "json");
		expect(mockContext.set).toHaveBeenCalledWith("props", mockProps);
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
				message: "Authentication required. Please provide a valid Bearer token.",
			},
			401,
			{
				"WWW-Authenticate": `Bearer realm="${request.url}", error="invalid_token"`,
			}
		);
		expect(next).not.toHaveBeenCalled();
	});

	it("should return 401 for token not found in access token store", async () => {
		mockKV.get.mockResolvedValueOnce(null);

		const request = new Request("http://localhost/mcp", {
			method: "POST",
			headers: { "Authorization": `Bearer ${VALID_TOKEN_B}` },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenCalledWith(`access_token:${VALID_TOKEN_B}`, "json");
		expect(mockContext.json).toHaveBeenCalledWith(
			{
				error: "unauthorized",
				message: "Invalid token.",
			},
			401
		);
		expect(next).not.toHaveBeenCalled();
	});

	it("should return 401 for token with invalid format (not 64 hex chars)", async () => {
		const request = new Request("http://localhost/mcp", {
			method: "POST",
			headers: { "Authorization": "Bearer invalid-token-format" },
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
			401
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
			headers: { "Authorization": `Bearer ${VALID_TOKEN_C}` },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenNthCalledWith(1, `access_token:${VALID_TOKEN_C}`, "json");
		expect(mockKV.get).toHaveBeenNthCalledWith(2, "session:expired-session", "json");
		expect(mockContext.json).toHaveBeenCalledWith(
			{
				error: "unauthorized",
				message: "Invalid token.",
			},
			401
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
			headers: { "Authorization": `Bearer ${VALID_TOKEN_D}` },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await expect(bearerAuth(mockContext as any, next)).rejects.toThrow("KV storage error");
	});

	it("should include WWW-Authenticate header for malformed bearer header", async () => {
		const request = new Request("http://localhost/mcp", {
			method: "POST",
			headers: { "Authorization": "Bearer" },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockContext.json).toHaveBeenCalledWith(
			{
				error: "unauthorized",
				message: "Authentication required. Please provide a valid Bearer token.",
			},
			401,
			{
				"WWW-Authenticate": `Bearer realm="${request.url}", error="invalid_token"`,
			}
		);
	});
});
