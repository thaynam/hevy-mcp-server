import { describe, it, expect, beforeEach, vi } from "vitest";
import { bearerAuth } from "../../src/middleware/auth.js";

// Mock the KV namespace
const mockKV = {
	get: vi.fn(),
	put: vi.fn(),
	delete: vi.fn(),
};

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
			headers: { "Authorization": "Bearer access-token-abc" },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenNthCalledWith(1, "access_token:access-token-abc", "json");
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
			headers: { "Authorization": "Bearer invalid-token" },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenCalledWith("access_token:invalid-token", "json");
		expect(mockContext.json).toHaveBeenCalledWith(
			{
				error: "unauthorized",
				message: "Invalid token.",
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
			headers: { "Authorization": "Bearer token-without-session" },
		});

		const mockContext = createMockContext(request);
		const next = vi.fn();

		await bearerAuth(mockContext as any, next);

		expect(mockKV.get).toHaveBeenNthCalledWith(1, "access_token:token-without-session", "json");
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
			headers: { "Authorization": "Bearer test-token" },
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
