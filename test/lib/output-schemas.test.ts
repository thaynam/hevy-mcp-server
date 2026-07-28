import { describe, it, expect } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
	HEVY_TOOL_OUTPUT_SCHEMAS,
	applyToolOutputSchemas,
} from "../../src/lib/output-schemas.js";
import {
	analyzeBodyProgress,
	analyzeTrainingSummary,
	analyzeProgressionDeltas,
	analyzePersonalRecords,
	compareWorkouts,
	findPreviousRoutineInstance,
	analyzeMuscleBalance,
} from "../../src/lib/analysis.js";

/** Parses a value against a tool's output shape (mirrors the SDK's validation). */
function parseOutput(tool: string, value: unknown) {
	return z.object(HEVY_TOOL_OUTPUT_SCHEMAS[tool]).safeParse(value);
}

describe("output-schemas", () => {
	describe("HEVY_TOOL_OUTPUT_SCHEMAS", () => {
		it("only covers read tools (never writes)", () => {
			for (const name of Object.keys(HEVY_TOOL_OUTPUT_SCHEMAS)) {
				const isWrite =
					name.startsWith("create_") ||
					name.startsWith("update_") ||
					name.startsWith("delete_");
				expect(isWrite, name).toBe(false);
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

		it("search_exercise_templates", () => {
			expect(
				parseOutput("search_exercise_templates", {
					query: "bench",
					count: 1,
					searched: 100,
					exercise_templates: [
						{
							id: "A1",
							title: "Bench Press",
							type: "weight_reps",
							primary_muscle_group: "chest",
							is_custom: false,
						},
					],
				}).success,
			).toBe(true);
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

		it("get_training_summary matches analyzeTrainingSummary output", () => {
			const summary = analyzeTrainingSummary(
				[
					{
						start_time: "2024-08-01T10:00:00Z",
						exercises: [{ sets: [{ weight_kg: 100, reps: 5 }] }],
					},
				],
				"2024-01-01",
				4,
			);
			expect(parseOutput("get_training_summary", summary).success).toBe(true);
		});

		it("get_training_summary matches an empty summary", () => {
			const summary = analyzeTrainingSummary([], "2024-01-01", 4);
			expect(parseOutput("get_training_summary", summary).success).toBe(true);
		});

		it("list envelopes accept paginated results with loose items", () => {
			expect(
				parseOutput("get_workouts", {
					page: 1,
					page_count: 2,
					workouts: [{ id: "w1", title: "Leg Day", exercises: [{ sets: [{}] }] }],
				}).success,
			).toBe(true);
			expect(
				parseOutput("get_routines", { page: 1, page_count: 1, routines: [] }).success,
			).toBe(true);
			expect(
				parseOutput("get_exercise_history", {
					exercise_history: [{ weight_kg: 100, reps: 5 }],
				}).success,
			).toBe(true);
		});

		it("single-resource reads accept found and not-found shapes", () => {
			expect(
				parseOutput("get_workout", {
					found: true,
					workout: { id: "w1", title: "Leg Day" },
				}).success,
			).toBe(true);
			expect(
				parseOutput("get_workout", { found: false, workout: null }).success,
			).toBe(true);
		});

		it("get_webhook_subscription accepts configured and unconfigured", () => {
			expect(
				parseOutput("get_webhook_subscription", {
					configured: true,
					url: "https://example.com/hevy",
					auth_token: "Bearer x",
				}).success,
			).toBe(true);
			expect(
				parseOutput("get_webhook_subscription", { configured: false }).success,
			).toBe(true);
		});

		it("get_progression_deltas matches analyzeProgressionDeltas output", () => {
			const result = analyzeProgressionDeltas(
				{
					id: "w_today",
					start_time: "2024-08-10T10:00:00Z",
					exercises: [
						{
							exercise_template_id: "BENCH",
							title: "Bench Press",
							sets: [
								{ type: "warmup", weight_kg: 60, reps: 10 },
								{ type: "normal", weight_kg: 100, reps: 5, rpe: 8 },
							],
						},
						{
							exercise_template_id: "NEW",
							sets: [{ type: "normal", reps: 12 }],
						},
					],
				},
				[
					{
						id: "w_prev",
						start_time: "2024-08-05T10:00:00Z",
						exercises: [
							{
								exercise_template_id: "BENCH",
								sets: [{ type: "normal", weight_kg: 97.5, reps: 5 }],
							},
						],
					},
				],
				{ scannedWorkouts: 2, truncated: false },
			);
			expect(parseOutput("get_progression_deltas", result).success).toBe(true);
		});

		it("get_progression_deltas accepts the empty (no session) shape", () => {
			expect(
				parseOutput("get_progression_deltas", {
					session: null,
					exercises: [],
					scanned_workouts: 0,
					exercises_without_previous: 0,
					truncated: false,
				}).success,
			).toBe(true);
		});

		it("get_personal_records", () => {
			const r = analyzePersonalRecords(
				[
					{
						id: "w1",
						start_time: "2024-08-01T10:00:00Z",
						exercises: [
							{ exercise_template_id: "BENCH", title: "Bench", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] },
							{ exercise_template_id: "PLANK", sets: [{ type: "normal", reps: 60 }] },
						],
					},
				],
				{ scannedWorkouts: 1, truncated: false },
			);
			expect(parseOutput("get_personal_records", r).success).toBe(true);
		});

		it("compare_workouts", () => {
			const r = compareWorkouts(
				{
					id: "A",
					start_time: "2024-08-10T10:00:00Z",
					end_time: "2024-08-10T11:00:00Z",
					exercises: [{ exercise_template_id: "BENCH", title: "Bench", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }],
				},
				{
					id: "B",
					start_time: "2024-08-03T10:00:00Z",
					exercises: [{ exercise_template_id: "SQUAT", sets: [{ type: "normal", weight_kg: 140, reps: 5 }] }],
				},
			);
			expect(parseOutput("compare_workouts", r).success).toBe(true);
		});

		it("get_previous_routine_instance", () => {
			const r = findPreviousRoutineInstance(
				[
					{ id: "w1", routine_id: "R1", start_time: "2024-08-10T10:00:00Z" },
					{ id: "w2", routine_id: "R1", start_time: "2024-08-03T10:00:00Z" },
				],
				"R1",
				{ scannedWorkouts: 2, truncated: false },
			);
			expect(parseOutput("get_previous_routine_instance", r).success).toBe(true);
		});

		it("get_muscle_balance", () => {
			const r = analyzeMuscleBalance(
				[{ start_time: "2024-08-10T10:00:00Z", exercises: [{ exercise_template_id: "BENCH", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }] }],
				{ BENCH: "chest" },
				"2024-08-01",
				{ truncated: false },
			);
			expect(parseOutput("get_muscle_balance", r).success).toBe(true);
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
