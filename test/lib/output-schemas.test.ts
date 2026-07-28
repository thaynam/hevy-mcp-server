import { describe, it, expect } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
	HEVY_TOOL_OUTPUT_SCHEMAS,
	applyToolOutputSchemas,
} from "../../src/lib/output-schemas.js";
import { analyzeBodyProgress } from "../../src/lib/analysis.js";

/** Parses a value against a tool's output shape (mirrors the SDK's validation). */
function parseOutput(tool: string, value: unknown) {
	return z.object(HEVY_TOOL_OUTPUT_SCHEMAS[tool]).safeParse(value);
}

describe("output-schemas", () => {
	describe("HEVY_TOOL_OUTPUT_SCHEMAS", () => {
		it("only covers read tools", () => {
			for (const name of Object.keys(HEVY_TOOL_OUTPUT_SCHEMAS)) {
				expect(name.startsWith("get_"), name).toBe(true);
			}
		});
	});

	describe("sample structured content validates", () => {
		it("get_workouts_count", () => {
			expect(parseOutput("get_workouts_count", { workout_count: 42 }).success).toBe(
				true,
			);
			expect(parseOutput("get_workouts_count", {}).success).toBe(false);
		});

		it("get_user_info accepts partial profiles", () => {
			expect(
				parseOutput("get_user_info", {
					id: "u1",
					name: "John",
					url: "https://hevy.com/user/john",
				}).success,
			).toBe(true);
			expect(parseOutput("get_user_info", {}).success).toBe(true);
		});

		it("get_body_measurements", () => {
			expect(
				parseOutput("get_body_measurements", {
					page: 1,
					page_count: 2,
					body_measurements: [{ date: "2024-08-14", weight_kg: 80.5, waist: null }],
				}).success,
			).toBe(true);
		});

		it("get_body_measurement (found and not-found)", () => {
			expect(
				parseOutput("get_body_measurement", {
					found: true,
					date: "2024-08-14",
					measurement: { date: "2024-08-14", weight_kg: 80.5 },
				}).success,
			).toBe(true);
			expect(
				parseOutput("get_body_measurement", {
					found: false,
					date: "2024-08-14",
					measurement: null,
				}).success,
			).toBe(true);
		});

		it("get_body_progress matches analyzeBodyProgress output", () => {
			const summary = analyzeBodyProgress(
				[
					{ date: "2024-08-01", weight_kg: 82 },
					{ date: "2024-09-01", weight_kg: 80 },
				],
				"2024-01-01",
			);
			expect(parseOutput("get_body_progress", summary).success).toBe(true);
		});

		it("get_body_progress matches an empty summary", () => {
			const summary = analyzeBodyProgress([], "2024-01-01");
			expect(parseOutput("get_body_progress", summary).success).toBe(true);
		});
	});

	describe("applyToolOutputSchemas", () => {
		it("attaches output schemas on a real McpServer registry", () => {
			const server = new McpServer({ name: "test", version: "1.0.0" });
			server.tool("get_workouts_count", {}, async () => ({
				content: [],
				structuredContent: { workout_count: 0 },
			}));

			applyToolOutputSchemas(server);

			const registry = (
				server as unknown as {
					_registeredTools: Record<string, { outputSchema?: unknown }>;
				}
			)._registeredTools;

			expect(registry.get_workouts_count.outputSchema).toBe(
				HEVY_TOOL_OUTPUT_SCHEMAS.get_workouts_count,
			);
		});

		it("no-ops safely when the registry is missing", () => {
			expect(() => applyToolOutputSchemas({} as never)).not.toThrow();
		});
	});
});
