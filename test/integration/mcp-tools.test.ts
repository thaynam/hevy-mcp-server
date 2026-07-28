import { describe, it, expect, beforeEach, vi } from "vitest";
import { HevyClient } from "../../src/lib/client.js";
import { mockFetchSuccess, mockFetchError } from "../setup.js";
import {
	mockWorkout,
	mockWorkoutsList,
	mockWorkoutEvents,
} from "../fixtures/workouts.js";
import { handleError } from "../../src/lib/errors.js";
import {
	validatePagination,
	validateISO8601Date,
	validateDate,
	validateWorkoutData,
	validateRoutineData,
	validateExerciseTemplate,
	validateBodyMeasurement,
	validateWebhookSubscription,
	PAGINATION_LIMITS,
} from "../../src/lib/transforms.js";
import {
	transformWorkoutToAPI,
	transformRoutineToAPI,
	transformExerciseTemplateToAPI,
	transformRoutineFolderToAPI,
	transformBodyMeasurementToAPI,
	transformWebhookSubscriptionToAPI,
} from "../../src/lib/schemas.js";

/**
 * Integration tests for MCP tools
 * 
 * These tests verify the end-to-end flow that users will experience:
 * 1. Valid inputs → successful responses
 * 2. Invalid inputs → proper error messages
 * 3. Edge cases → appropriate handling
 * 
 * Note: Since MCP tools are Cloudflare Workers Durable Objects, we test
 * the underlying logic (client calls, validation, error handling, transformations)
 * that powers each tool rather than the tool handlers themselves.
 */
describe("MCP Tools Integration Tests", () => {
	let client: HevyClient;

	beforeEach(() => {
		// Reset all mocks before each test
		vi.clearAllMocks();

		// Create Hevy API client with test API key
		client = new HevyClient({ apiKey: "test-api-key" });
	});

	// ============================================
	// WORKOUT TOOLS
	// ============================================

	describe("get_workouts", () => {
		it("should successfully retrieve workouts with pagination", async () => {
			mockFetchSuccess(mockWorkoutsList);

			validatePagination(1, 10, PAGINATION_LIMITS.WORKOUTS);
			const workouts = await client.getWorkouts({ page: 1, pageSize: 10 });

			expect(workouts.workouts).toHaveLength(3);
			expect(workouts.page).toBe(1);
		});

		it("should handle empty workout list", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, workouts: [] });

			const workouts = await client.getWorkouts({});
			expect(workouts.workouts).toEqual([]);
		});

		it("should throw error for invalid pagination", async () => {
			try {
				validatePagination(0, 10, PAGINATION_LIMITS.WORKOUTS);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("Page must be 1 or greater");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle API errors", async () => {
			mockFetchError(401, "Unauthorized");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Unauthorized");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("get_workout", () => {
		it("should successfully retrieve a single workout", async () => {
			mockFetchSuccess(mockWorkout);

			const workout = await client.getWorkout("b459cba5-cd6d-463c-abd6-54f8eafcadcb");

			expect(workout.id).toBe(mockWorkout.id);
			expect(workout.exercises).toHaveLength(2);
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getWorkout("non-existent-id");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_workout", () => {
		it("should successfully create a workout with full end-to-end flow", async () => {
			const createdWorkout = {
				id: "new-workout-id",
				title: "Test Workout",
				exercises: [],
			};
			mockFetchSuccess(createdWorkout);

			const workoutData = {
				title: "Test Workout",
				start_time: "2024-08-14T12:00:00Z",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [
					{
						title: "Bench Press",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			// Step 1: Validate
			validateWorkoutData(workoutData);
			// Step 2: Transform
			const apiPayload = transformWorkoutToAPI(workoutData);
			// Step 3: API call
			const workout = await client.createWorkout(apiPayload);

			expect(workout.id).toBe("new-workout-id");
		});

		it("should throw error for invalid dates", async () => {
			const workoutData = {
				title: "Test",
				start_time: "invalid-date",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [
					{
						title: "Test",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			try {
				validateWorkoutData(workoutData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("ISO 8601 format");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error when end_time is before start_time", async () => {
			const workoutData = {
				title: "Test",
				start_time: "2024-08-14T12:30:00Z",
				end_time: "2024-08-14T12:00:00Z",
				exercises: [
					{
						title: "Test",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			try {
				validateWorkoutData(workoutData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("end_time must be after start_time");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for empty exercises", async () => {
			const workoutData = {
				title: "Test",
				start_time: "2024-08-14T12:00:00Z",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [],
			};

			try {
				validateWorkoutData(workoutData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("At least one exercise is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for invalid RPE", async () => {
			const workoutData = {
				title: "Test",
				start_time: "2024-08-14T12:00:00Z",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [
					{
						title: "Test",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10, rpe: 11 }],
					},
				],
			};

			try {
				validateWorkoutData(workoutData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("RPE must be one of");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for negative values", async () => {
			const workoutData = {
				title: "Test",
				start_time: "2024-08-14T12:00:00Z",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [
					{
						title: "Test",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: -100, reps: 10 }],
					},
				],
			};

			try {
				validateWorkoutData(workoutData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("cannot be negative");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("update_workout", () => {
		it("should successfully update a workout", async () => {
			mockFetchSuccess({ id: "workout-id", title: "Updated" });

			const workoutData = {
				title: "Updated",
				start_time: "2024-08-14T12:00:00Z",
				end_time: "2024-08-14T12:30:00Z",
				exercises: [
					{
						title: "Test",
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			validateWorkoutData(workoutData);
			const apiPayload = transformWorkoutToAPI(workoutData);
			const workout = await client.updateWorkout("workout-id", apiPayload);

			expect(workout.id).toBe("workout-id");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.updateWorkout("non-existent-id", {});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("get_workouts_count", () => {
		it("should successfully retrieve workout count", async () => {
			mockFetchSuccess({ workout_count: 42 });

			const result = await client.getWorkoutsCount();

			expect(result.workout_count).toBe(42);
		});

		it("should handle zero count", async () => {
			mockFetchSuccess({ workout_count: 0 });

			const result = await client.getWorkoutsCount();

			expect(result.workout_count).toBe(0);
		});
	});

	describe("get_workout_events", () => {
		it("should successfully retrieve workout events", async () => {
			mockFetchSuccess(mockWorkoutEvents);

			validatePagination(1, 5, PAGINATION_LIMITS.WORKOUT_EVENTS);
			const events = await client.getWorkoutEvents({ page: 1, pageSize: 5 });

			expect(events.events).toHaveLength(2);
		});

		it("should validate since parameter", async () => {
			try {
				validateISO8601Date("invalid-date", "since");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("ISO 8601 format");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle empty events list", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, events: [] });

			const events = await client.getWorkoutEvents({});

			expect(events.events).toEqual([]);
		});
	});

	// ============================================
	// ROUTINE TOOLS
	// ============================================

	describe("get_routines", () => {
		it("should successfully retrieve routines", async () => {
			const mockRoutines = {
				page: 1,
				page_count: 1,
				routines: [{ id: "routine-1", title: "Push Day", exercises: [] }],
			};
			mockFetchSuccess(mockRoutines);

			validatePagination(1, 5, PAGINATION_LIMITS.ROUTINES);
			const routines = await client.getRoutines({ page: 1, pageSize: 5 });

			expect(routines.routines).toHaveLength(1);
		});

		it("should handle empty routines list", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, routines: [] });

			const routines = await client.getRoutines({});

			expect(routines.routines).toEqual([]);
		});
	});

	describe("get_routine", () => {
		it("should successfully retrieve a routine", async () => {
			const mockRoutine = {
				routine: { id: "routine-1", title: "Push Day", exercises: [] },
			};
			mockFetchSuccess(mockRoutine);

			const result = await client.getRoutine("routine-1");

			expect(result.routine.id).toBe("routine-1");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getRoutine("non-existent-id");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_routine", () => {
		it("should successfully create a routine with full end-to-end flow", async () => {
			mockFetchSuccess({ id: "new-routine-id", title: "My Routine" });

			const routineData = {
				title: "My Routine",
				exercises: [
					{
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			// Step 1: Validate
			validateRoutineData(routineData);
			// Step 2: Transform
			const apiPayload = transformRoutineToAPI(routineData);
			// Step 3: API call
			const routine = await client.createRoutine(apiPayload);

			expect(routine.id).toBe("new-routine-id");
		});

		it("should throw error for empty title", async () => {
			const routineData = {
				title: "",
				exercises: [
					{
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			try {
				validateRoutineData(routineData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("title is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for empty exercises", async () => {
			const routineData = {
				title: "My Routine",
				exercises: [],
			};

			try {
				validateRoutineData(routineData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("At least one exercise is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for invalid rep range", async () => {
			const routineData = {
				title: "My Routine",
				exercises: [
					{
						exercise_template_id: "123",
						sets: [
							{
								type: "normal" as const,
								weight_kg: 100,
								rep_range: { start: 12, end: 8 }, // Invalid
							},
						],
					},
				],
			};

			try {
				validateRoutineData(routineData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("rep_range");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("update_routine", () => {
		it("should successfully update a routine", async () => {
			mockFetchSuccess({ id: "routine-id", title: "Updated" });

			const routineData = {
				title: "Updated",
				exercises: [
					{
						exercise_template_id: "123",
						sets: [{ type: "normal" as const, weight_kg: 100, reps: 10 }],
					},
				],
			};

			validateRoutineData(routineData);
			const apiPayload = transformRoutineToAPI(routineData);
			const routine = await client.updateRoutine("routine-id", apiPayload);

			expect(routine.id).toBe("routine-id");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.updateRoutine("non-existent-id", {});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	// ============================================
	// EXERCISE TEMPLATE TOOLS
	// ============================================

	describe("get_exercise_templates", () => {
		it("should successfully retrieve exercise templates", async () => {
			const mockTemplates = {
				page: 1,
				page_count: 1,
				exercise_templates: [
					{ id: "template-1", title: "Bench Press", type: "weight_reps" },
				],
			};
			mockFetchSuccess(mockTemplates);

			validatePagination(1, 20, PAGINATION_LIMITS.EXERCISE_TEMPLATES);
			const templates = await client.getExerciseTemplates({ page: 1, pageSize: 20 });

			expect(templates.exercise_templates).toHaveLength(1);
		});

		it("should support higher page size limit (100)", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, exercise_templates: [] });

			validatePagination(1, 100, PAGINATION_LIMITS.EXERCISE_TEMPLATES);
			const templates = await client.getExerciseTemplates({ pageSize: 100 });

			expect(templates.exercise_templates).toEqual([]);
		});

		it("should throw error for page size exceeding 100", async () => {
			try {
				validatePagination(1, 101, PAGINATION_LIMITS.EXERCISE_TEMPLATES);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("Page size cannot exceed 100");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("get_exercise_template", () => {
		it("should successfully retrieve a template", async () => {
			const mockTemplate = {
				id: "template-1",
				title: "Bench Press",
				type: "weight_reps",
			};
			mockFetchSuccess(mockTemplate);

			const template = await client.getExerciseTemplate("template-1");

			expect(template.id).toBe("template-1");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getExerciseTemplate("non-existent-id");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_exercise_template", () => {
		it("should successfully create a custom exercise template", async () => {
			mockFetchSuccess({ id: "new-template-id", title: "My Exercise" });

			const templateData = {
				title: "My Exercise",
				exercise_type: "weight_reps" as const,
				equipment_category: "dumbbell" as const,
				muscle_group: "chest" as const,
			};

			// Step 1: Validate
			validateExerciseTemplate(templateData);
			// Step 2: Transform
			const apiPayload = transformExerciseTemplateToAPI(templateData);
			// Step 3: API call
			const template = await client.createExerciseTemplate(apiPayload);

			expect(template.id).toBe("new-template-id");
		});

		it("should throw error for empty title", async () => {
			const templateData = {
				title: "",
				exercise_type: "weight_reps" as const,
				equipment_category: "dumbbell" as const,
				muscle_group: "chest" as const,
			};

			try {
				validateExerciseTemplate(templateData);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("title is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle templates with secondary muscles", async () => {
			mockFetchSuccess({ id: "new-template-id", title: "My Exercise" });

			const templateData = {
				title: "My Exercise",
				exercise_type: "weight_reps" as const,
				equipment_category: "barbell" as const,
				muscle_group: "chest" as const,
				other_muscles: ["triceps" as const, "shoulders" as const],
			};

			validateExerciseTemplate(templateData);
			const apiPayload = transformExerciseTemplateToAPI(templateData);
			const template = await client.createExerciseTemplate(apiPayload);

			expect(template.id).toBe("new-template-id");
		});
	});

	describe("get_exercise_history", () => {
		it("should successfully retrieve exercise history", async () => {
			const mockHistory = {
				exercise_history: [
					{
						workout_title: "Push Day",
						weight_kg: 100,
						reps: 10,
					},
				],
			};
			mockFetchSuccess(mockHistory);

			const history = await client.getExerciseHistory("template-1");

			expect(history.exercise_history).toHaveLength(1);
		});

		it("should validate date range", async () => {
			try {
				validateISO8601Date("invalid-date", "startDate");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("ISO 8601 format");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle empty history", async () => {
			mockFetchSuccess({ exercise_history: [] });

			const history = await client.getExerciseHistory("template-1");

			expect(history.exercise_history).toEqual([]);
		});
	});

	// ============================================
	// ROUTINE FOLDER TOOLS
	// ============================================

	describe("get_routine_folders", () => {
		it("should successfully retrieve routine folders", async () => {
			const mockFolders = {
				page: 1,
				page_count: 1,
				routine_folders: [{ id: "folder-1", title: "Upper Body", index: 0 }],
			};
			mockFetchSuccess(mockFolders);

			validatePagination(1, 10, PAGINATION_LIMITS.ROUTINE_FOLDERS);
			const folders = await client.getRoutineFolders({ page: 1, pageSize: 10 });

			expect(folders.routine_folders).toHaveLength(1);
		});

		it("should handle empty folders list", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, routine_folders: [] });

			const folders = await client.getRoutineFolders({});

			expect(folders.routine_folders).toEqual([]);
		});
	});

	describe("get_routine_folder", () => {
		it("should successfully retrieve a routine folder", async () => {
			const mockFolder = { id: "folder-1", title: "Upper Body", index: 0 };
			mockFetchSuccess(mockFolder);

			const folder = await client.getRoutineFolder("folder-1");

			expect(folder.id).toBe("folder-1");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getRoutineFolder("non-existent-id");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_routine_folder", () => {
		it("should successfully create a routine folder", async () => {
			mockFetchSuccess({ id: "new-folder-id", title: "My Folder" });

			const folderData = { title: "My Folder" };
			const apiPayload = transformRoutineFolderToAPI(folderData);
			const folder = await client.createRoutineFolder(apiPayload);

			expect(folder.id).toBe("new-folder-id");
		});
	});

	// ============================================
	// USER TOOLS
	// ============================================

	describe("get_user_info", () => {
		it("should successfully retrieve user info", async () => {
			mockFetchSuccess({
				data: { id: "u1", name: "John", url: "https://hevy.com/user/john" },
			});

			const result = await client.getUserInfo();

			expect(result.data.id).toBe("u1");
			expect(result.data.name).toBe("John");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getUserInfo();
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	// ============================================
	// BODY MEASUREMENT TOOLS
	// ============================================

	describe("get_body_measurements", () => {
		it("should successfully retrieve body measurements with pagination", async () => {
			const mockMeasurements = {
				page: 1,
				page_count: 1,
				body_measurements: [{ date: "2024-08-14", weight_kg: 80.5, waist: 80 }],
			};
			mockFetchSuccess(mockMeasurements);

			validatePagination(1, 10, PAGINATION_LIMITS.BODY_MEASUREMENTS);
			const measurements = await client.getBodyMeasurements({ page: 1, pageSize: 10 });

			expect(measurements.body_measurements).toHaveLength(1);
			expect(measurements.body_measurements[0].weight_kg).toBe(80.5);
		});

		it("should throw error for page size exceeding 10", async () => {
			try {
				validatePagination(1, 11, PAGINATION_LIMITS.BODY_MEASUREMENTS);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("Page size cannot exceed 10");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle empty measurements list", async () => {
			mockFetchSuccess({ page: 1, page_count: 1, body_measurements: [] });

			const measurements = await client.getBodyMeasurements({});

			expect(measurements.body_measurements).toEqual([]);
		});
	});

	describe("get_body_measurement", () => {
		it("should successfully retrieve a single measurement by date", async () => {
			mockFetchSuccess({ date: "2024-08-14", weight_kg: 80.5 });

			validateDate("2024-08-14", "date");
			const measurement = await client.getBodyMeasurement("2024-08-14");

			expect(measurement.date).toBe("2024-08-14");
		});

		it("should validate the date format", async () => {
			try {
				validateDate("14/08/2024", "date");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("YYYY-MM-DD format");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getBodyMeasurement("2024-08-14");
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_body_measurement", () => {
		it("should successfully create a measurement with full end-to-end flow", async () => {
			mockFetchSuccess({}, 200);

			const measurementData = {
				date: "2024-08-14",
				weight_kg: 80.5,
				waist: 80,
			};

			// Step 1: Validate
			validateBodyMeasurement(measurementData, { requireDate: true });
			// Step 2: Transform
			const apiPayload = transformBodyMeasurementToAPI(measurementData);
			// Step 3: API call
			await client.createBodyMeasurement(apiPayload);

			const callArgs = (global.fetch as any).mock.calls[0];
			const body = JSON.parse(callArgs[1].body);
			expect(body.date).toBe("2024-08-14");
			expect(body.weight_kg).toBe(80.5);
		});

		it("should throw error when date is missing", async () => {
			try {
				validateBodyMeasurement({ weight_kg: 80.5 }, { requireDate: true });
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("date is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for negative metric values", async () => {
			try {
				validateBodyMeasurement(
					{ date: "2024-08-14", weight_kg: -5 },
					{ requireDate: true },
				);
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("cannot be negative");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 409 when a measurement already exists for the date", async () => {
			mockFetchError(409, "Conflict", {
				error: "A measurement for this date already exists",
			});

			try {
				await client.createBodyMeasurement({ date: "2024-08-14" });
				expect.fail("Should have thrown");
			} catch (error) {
				expect((error as any).status).toBe(409);
			}
		});
	});

	describe("update_body_measurement", () => {
		it("should successfully update a measurement (date in path, flat body)", async () => {
			mockFetchSuccess({}, 200);

			const measurementData = { weight_kg: 81, waist: 79 };

			validateDate("2024-08-14", "date");
			validateBodyMeasurement(measurementData);
			const apiPayload = transformBodyMeasurementToAPI(measurementData);
			await client.updateBodyMeasurement("2024-08-14", apiPayload);

			const callArgs = (global.fetch as any).mock.calls[0];
			expect(callArgs[0]).toBe(
				"https://api.hevyapp.com/v1/body_measurements/2024-08-14",
			);
			const body = JSON.parse(callArgs[1].body);
			expect(body.weight_kg).toBe(81);
			expect(body).not.toHaveProperty("date");
		});

		it("should handle 404 errors", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.updateBodyMeasurement("2024-08-14", { weight_kg: 81 });
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	// ============================================
	// WEBHOOK SUBSCRIPTION TOOLS
	// ============================================

	describe("get_webhook_subscription", () => {
		it("should successfully retrieve the current subscription", async () => {
			mockFetchSuccess({
				url: "https://example.com/hevy-webhook",
				auth_token: "Bearer mytoken",
			});

			const subscription = await client.getWebhookSubscription();

			expect(subscription.url).toBe("https://example.com/hevy-webhook");
		});

		it("should handle 404 when no subscription exists", async () => {
			mockFetchError(404, "Not Found");

			try {
				await client.getWebhookSubscription();
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Resource not found");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("create_webhook_subscription", () => {
		it("should successfully create a subscription with full end-to-end flow", async () => {
			mockFetchSuccess({}, 201);

			const subscriptionData = {
				url: "https://example.com/hevy-webhook",
				auth_token: "Bearer mytoken",
			};

			// Step 1: Validate
			validateWebhookSubscription(subscriptionData);
			// Step 2: Transform (auth_token -> authToken)
			const apiPayload = transformWebhookSubscriptionToAPI(subscriptionData);
			// Step 3: API call
			await client.createWebhookSubscription(apiPayload);

			const callArgs = (global.fetch as any).mock.calls[0];
			const body = JSON.parse(callArgs[1].body);
			expect(body.url).toBe("https://example.com/hevy-webhook");
			expect(body.authToken).toBe("Bearer mytoken");
			expect(body).not.toHaveProperty("auth_token");
		});

		it("should throw error for empty url", async () => {
			try {
				validateWebhookSubscription({ url: "" });
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("url is required");
				expect(result.isError).toBe(true);
			}
		});

		it("should throw error for a non-http(s) url", async () => {
			try {
				validateWebhookSubscription({ url: "ftp://example.com" });
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("http(s) URL");
				expect(result.isError).toBe(true);
			}
		});
	});

	describe("delete_webhook_subscription", () => {
		it("should successfully delete the subscription", async () => {
			mockFetchSuccess({}, 200);

			await client.deleteWebhookSubscription();

			const callArgs = (global.fetch as any).mock.calls[0];
			expect(callArgs[1].method).toBe("DELETE");
		});

		it("should handle errors", async () => {
			mockFetchError(500, "Internal Server Error");

			try {
				await client.deleteWebhookSubscription();
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.isError).toBe(true);
			}
		});
	});

	// ============================================
	// API ERROR HANDLING
	// ============================================

	describe("API Error Handling", () => {
		it("should handle 401 Unauthorized errors", async () => {
			mockFetchError(401, "Unauthorized");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
			expect(result.content[0].text).toContain("❌ Unauthorized - Invalid API key");
			expect(result.content[0].text).toContain("Verify your Hevy API key is configured at /setup");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 403 Forbidden errors", async () => {
			mockFetchError(403, "Forbidden");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Limit exceeded or unauthorized");
				expect(result.content[0].text).toContain("exceeded API rate limits");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 429 Rate Limit errors", async () => {
			mockFetchError(429, "Too Many Requests");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Rate limit exceeded");
				expect(result.content[0].text).toContain("Wait before making more requests");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 500 Internal Server errors", async () => {
			mockFetchError(500, "Internal Server Error");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("❌ Hevy API error");
				expect(result.content[0].text).toContain("temporary Hevy API issue");
				expect(result.isError).toBe(true);
			}
		});

		it("should handle 503 Service Unavailable errors", async () => {
			mockFetchError(503, "Service Unavailable");

			try {
				await client.getWorkouts({});
				expect.fail("Should have thrown");
			} catch (error) {
				const result = handleError(error);
				expect(result.content[0].text).toContain("Hevy API is temporarily unavailable");
				expect(result.isError).toBe(true);
			}
		});
	});
});
