import { describe, it, expect } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
	readOnlyAnnotations,
	createAnnotations,
	updateAnnotations,
	destructiveAnnotations,
	HEVY_TOOL_ANNOTATIONS,
	applyToolAnnotations,
} from "../../src/lib/tool-annotations.js";

describe("tool-annotations", () => {
	describe("annotation factories", () => {
		it("readOnlyAnnotations marks the tool read-only and closed-world", () => {
			expect(readOnlyAnnotations("Get Workouts")).toEqual({
				title: "Get Workouts",
				readOnlyHint: true,
				openWorldHint: false,
			});
		});

		it("createAnnotations is a non-destructive, non-idempotent write", () => {
			expect(createAnnotations("Create Workout")).toEqual({
				title: "Create Workout",
				readOnlyHint: false,
				destructiveHint: false,
				idempotentHint: false,
				openWorldHint: false,
			});
		});

		it("updateAnnotations is a destructive, idempotent write", () => {
			const a = updateAnnotations("Update Workout");
			expect(a.destructiveHint).toBe(true);
			expect(a.idempotentHint).toBe(true);
			expect(a.readOnlyHint).toBe(false);
		});

		it("destructiveAnnotations is destructive and idempotent", () => {
			const a = destructiveAnnotations("Delete Webhook Subscription");
			expect(a.destructiveHint).toBe(true);
			expect(a.idempotentHint).toBe(true);
		});
	});

	describe("HEVY_TOOL_ANNOTATIONS map", () => {
		it("covers all 33 tools", () => {
			expect(Object.keys(HEVY_TOOL_ANNOTATIONS)).toHaveLength(33);
		});

		it("marks every get_* tool read-only", () => {
			for (const [name, ann] of Object.entries(HEVY_TOOL_ANNOTATIONS)) {
				if (name.startsWith("get_")) {
					expect(ann.readOnlyHint, name).toBe(true);
				}
			}
		});

		it("marks every write tool as not read-only", () => {
			for (const [name, ann] of Object.entries(HEVY_TOOL_ANNOTATIONS)) {
				if (
					name.startsWith("create_") ||
					name.startsWith("update_") ||
					name.startsWith("delete_")
				) {
					expect(ann.readOnlyHint, name).toBe(false);
				}
			}
		});

		it("marks update_* and delete_* as destructive", () => {
			expect(HEVY_TOOL_ANNOTATIONS.update_workout.destructiveHint).toBe(true);
			expect(
				HEVY_TOOL_ANNOTATIONS.delete_webhook_subscription.destructiveHint,
			).toBe(true);
		});

		it("marks create_* as non-destructive", () => {
			expect(HEVY_TOOL_ANNOTATIONS.create_workout.destructiveHint).toBe(false);
		});
	});

	describe("applyToolAnnotations", () => {
		it("attaches annotations to matching registered tools", () => {
			const registry: Record<string, { annotations?: unknown }> = {
				get_workouts: {},
				delete_webhook_subscription: {},
				not_a_hevy_tool: {},
			};
			const fakeServer = { _registeredTools: registry } as never;

			applyToolAnnotations(fakeServer);

			expect(registry.get_workouts.annotations).toEqual(
				HEVY_TOOL_ANNOTATIONS.get_workouts,
			);
			expect(registry.delete_webhook_subscription.annotations).toEqual(
				HEVY_TOOL_ANNOTATIONS.delete_webhook_subscription,
			);
			// Unknown tools are left untouched
			expect(registry.not_a_hevy_tool.annotations).toBeUndefined();
		});

		it("no-ops safely when the registry is missing", () => {
			expect(() => applyToolAnnotations({} as never)).not.toThrow();
		});

		it("attaches annotations on a real McpServer registry", () => {
			const server = new McpServer({ name: "test", version: "1.0.0" });
			server.tool("get_workouts", {}, async () => ({ content: [] }));
			server.tool("delete_webhook_subscription", {}, async () => ({
				content: [],
			}));

			applyToolAnnotations(server);

			// Read back through the same internal registry the SDK uses for tools/list
			const registry = (
				server as unknown as {
					_registeredTools: Record<string, { annotations?: unknown }>;
				}
			)._registeredTools;

			expect(registry.get_workouts.annotations).toEqual(
				HEVY_TOOL_ANNOTATIONS.get_workouts,
			);
			expect(registry.delete_webhook_subscription.annotations).toEqual(
				HEVY_TOOL_ANNOTATIONS.delete_webhook_subscription,
			);
		});
	});
});
