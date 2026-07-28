import { describe, it, expect } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
	describeTool,
	HEVY_TOOL_DESCRIPTIONS,
	applyToolDescriptions,
} from "../../src/lib/tool-descriptions.js";
import { HEVY_TOOL_ANNOTATIONS } from "../../src/lib/tool-annotations.js";

describe("tool-descriptions", () => {
	describe("describeTool", () => {
		it("joins summary, useCase and note", () => {
			expect(
				describeTool({
					summary: "Read-only. Lists workouts.",
					useCase: "Use to browse history.",
					note: "pageSize max 10.",
				}),
			).toBe(
				"Read-only. Lists workouts. Use to browse history. Note: pageSize max 10.",
			);
		});

		it("omits missing optional parts", () => {
			expect(describeTool({ summary: "Creates a folder." })).toBe(
				"Creates a folder.",
			);
		});
	});

	describe("HEVY_TOOL_DESCRIPTIONS map", () => {
		it("covers exactly the annotated tools (all 25)", () => {
			expect(Object.keys(HEVY_TOOL_DESCRIPTIONS).sort()).toEqual(
				Object.keys(HEVY_TOOL_ANNOTATIONS).sort(),
			);
		});

		it("has a non-empty description for every tool", () => {
			for (const [name, description] of Object.entries(
				HEVY_TOOL_DESCRIPTIONS,
			)) {
				expect(description.length, name).toBeGreaterThan(0);
			}
		});
	});

	describe("applyToolDescriptions", () => {
		it("attaches descriptions on a real McpServer registry", () => {
			const server = new McpServer({ name: "test", version: "1.0.0" });
			server.tool("get_workouts", {}, async () => ({ content: [] }));

			applyToolDescriptions(server);

			const registry = (
				server as unknown as {
					_registeredTools: Record<string, { description?: string }>;
				}
			)._registeredTools;

			expect(registry.get_workouts.description).toBe(
				HEVY_TOOL_DESCRIPTIONS.get_workouts,
			);
		});

		it("no-ops safely when the registry is missing", () => {
			expect(() => applyToolDescriptions({} as never)).not.toThrow();
		});
	});
});
