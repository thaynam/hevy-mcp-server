import { HevyApiError } from "./client.js";
import type { McpToolResponse } from "./errors.js";

/**
 * Error policy for Hevy reads.
 *
 * The Hevy API returns 404 for a few outcomes that are perfectly normal from a
 * caller's point of view — a single resource that doesn't exist, a date with no
 * body measurement logged, or no webhook subscription configured. Surfacing
 * those as hard errors (isError: true) makes an AI client treat a legitimate
 * "nothing here" answer as a failure. This helper lets read tools convert an
 * expected 404 into a clean, non-error result instead.
 */

/** True when the error is a Hevy 404 (resource or page not found). */
export function isNotFoundError(error: unknown): error is HevyApiError {
	return error instanceof HevyApiError && error.status === 404;
}

/**
 * Builds a clean, non-error MCP response for an expected "not found" outcome.
 * isError is intentionally left unset — a missing resource is a valid answer to
 * a read, not a tool failure.
 */
export function notFoundResponse(message: string): McpToolResponse {
	return {
		content: [
			{
				type: "text",
				text: message,
			},
		],
	};
}
