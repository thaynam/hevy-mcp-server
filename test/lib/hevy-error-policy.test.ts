import { describe, it, expect } from "vitest";
import { HevyApiError } from "../../src/lib/client.js";
import { ValidationError } from "../../src/lib/transforms.js";
import {
	isNotFoundError,
	notFoundResponse,
} from "../../src/lib/hevy-error-policy.js";

describe("hevy-error-policy", () => {
	describe("isNotFoundError", () => {
		it("is true for a Hevy 404", () => {
			expect(isNotFoundError(new HevyApiError("Not Found", 404))).toBe(true);
		});

		it("is false for other Hevy statuses", () => {
			expect(isNotFoundError(new HevyApiError("Server Error", 500))).toBe(false);
			expect(isNotFoundError(new HevyApiError("Unauthorized", 401))).toBe(false);
		});

		it("is false for non-Hevy errors", () => {
			expect(isNotFoundError(new ValidationError("bad"))).toBe(false);
			expect(isNotFoundError(new Error("nope"))).toBe(false);
			expect(isNotFoundError(null)).toBe(false);
			expect(isNotFoundError(undefined)).toBe(false);
		});
	});

	describe("notFoundResponse", () => {
		it("returns a clean, non-error response with the message", () => {
			const res = notFoundResponse("No body measurement found for 2024-08-14");

			expect(res.content[0].text).toBe(
				"No body measurement found for 2024-08-14",
			);
			// A missing resource is a valid read answer, not a tool failure
			expect(res.isError).toBeUndefined();
		});
	});
});
