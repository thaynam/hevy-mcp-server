import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { HevyClient } from "./lib/client.js";
import {
  CreateWorkoutSchema,
  UpdateWorkoutSchema,
  CreateRoutineSchema,
  UpdateRoutineSchema,
  CreateExerciseTemplateSchema,
  CreateRoutineFolderSchema,
  CreateBodyMeasurementSchema,
  UpdateBodyMeasurementSchema,
  CreateWebhookSubscriptionSchema,
  transformWorkoutToAPI,
  transformRoutineToAPI,
  transformExerciseTemplateToAPI,
  transformRoutineFolderToAPI,
  transformBodyMeasurementToAPI,
  transformWebhookSubscriptionToAPI,
} from "./lib/schemas.js";
import {
  ValidationError,
  validatePagination,
  validateISO8601Date,
  validateDate,
  validateWorkoutData,
  validateRoutineData,
  validateExerciseTemplate,
  validateBodyMeasurement,
  validateWebhookSubscription,
  PAGINATION_LIMITS,
} from "./lib/transforms.js";
import { handleError } from "./lib/errors.js";
import {
  analyzeBodyProgress,
  formatBodyProgress,
  analyzeTrainingSummary,
  formatTrainingSummary,
  analyzeProgressionDeltas,
  formatProgressionDeltas,
  analyzeWindowProgression,
  formatWindowProgression,
  analyzePersonalRecords,
  formatPersonalRecords,
  compareWorkouts,
  findPreviousRoutineInstance,
  analyzeMuscleBalance,
} from "./lib/analysis.js";
import { filterExerciseTemplates } from "./lib/exercise-search.js";
import { isNotFoundError } from "./lib/hevy-error-policy.js";
import { applyToolAnnotations } from "./lib/tool-annotations.js";
import { applyToolDescriptions } from "./lib/tool-descriptions.js";
import { applyToolOutputSchemas } from "./lib/output-schemas.js";
import type { Props } from "./utils.js";

// Define our MCP agent with Hevy API tools and OAuth support
// Env is globally defined in worker-configuration.d.ts by Wrangler
export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
  server = new McpServer({
    name: "Hevy API",
    version: "3.1.0",
    description:
      "Multi-user remote MCP server for Hevy fitness tracking API with OAuth authentication",
  });

  private client!: HevyClient;

  async init() {
    // Check if user is authenticated
    if (!this.props || !this.props.hevyApiKey) {
      const setupHint = this.props?.baseUrl
        ? ` Visit ${this.props.baseUrl} to get started.`
        : " Visit your server URL to authenticate.";
      throw new Error(
        "Authentication required. Please authenticate via OAuth to use the Hevy MCP server." +
          setupHint,
      );
    }

    // Initialize Hevy API client with user-specific API key.
    // Enable retries so transient Hevy rate limits / 5xx don't surface as
    // hard tool failures.
    this.client = new HevyClient({
      apiKey: this.props.hevyApiKey,
      maxRetries: 3,
    });

    // ============================================
    // WORKOUTS
    // ============================================

    this.server.tool(
      "get_workouts",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 10)")
          .default(10),
      },
      async ({ page, page_size }) => {
        try {
          // Validate pagination parameters
          validatePagination(page, page_size, PAGINATION_LIMITS.WORKOUTS);

          const workouts = await this.client.getWorkouts({
            page,
            pageSize: page_size,
          });

          const workoutDetails =
            workouts.workouts
              ?.map((workout: any, index: number) => {
                return `Workout ${index + 1}: ${workout.title || "Untitled"}\n  ID: ${workout.id}\n  Date: ${workout.start_time}`;
              })
              .join("\n") || "No workouts found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${workouts.workouts?.length || 0} workouts (page ${workouts.page} of ${workouts.page_count})`,
              },
              {
                type: "text",
                text: workoutDetails,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(workouts.workouts, null, 2)}`,
              },
            ],
            structuredContent: {
              page: workouts.page,
              page_count: workouts.page_count,
              workouts: workouts.workouts ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_workout",
      {
        workout_id: z.string().describe("The ID of the workout to retrieve"),
      },
      async ({ workout_id }) => {
        try {
          const workout = await this.client.getWorkout(workout_id);

          return {
            content: [
              {
                type: "text",
                text: `Workout: ${workout.title || "Untitled"}\nID: ${workout.id}\nExercises: ${workout.exercises?.length || 0}`,
              },
              {
                type: "text",
                text: JSON.stringify(workout, null, 2),
              },
            ],
            structuredContent: { found: true, workout },
          };
        } catch (error) {
          if (isNotFoundError(error)) {
            return {
              content: [
                {
                  type: "text",
                  text: `No workout found with ID ${workout_id}`,
                },
              ],
              structuredContent: { found: false, workout: null },
            };
          }
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "create_workout",
      CreateWorkoutSchema.shape,
      async (args) => {
        try {
          // Validate workout data including dates, exercises, and RPE values
          validateWorkoutData(args);

          const workout = await this.client.createWorkout(
            transformWorkoutToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully logged workout: ${workout.title}`,
              },
              {
                type: "text",
                text: `Workout ID: ${workout.id}\nExercises: ${workout.exercises?.length || 0}\nStarted: ${args.start_time}`,
              },
              {
                type: "text",
                text: `\n\nWorkout data:\n${JSON.stringify(workout, null, 2)}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "update_workout",
      {
        workout_id: z.string().describe("The ID of the workout to update"),
        ...UpdateWorkoutSchema.shape,
      },
      async (args) => {
        try {
          const { workout_id, ...workoutData } = args;

          // Validate workout data including dates, exercises, and RPE values
          validateWorkoutData(workoutData);

          const workout = await this.client.updateWorkout(
            workout_id,
            transformWorkoutToAPI(workoutData),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully updated workout: ${workout.title}`,
              },
              {
                type: "text",
                text: `Workout ID: ${workout.id}\nExercises: ${workout.exercises?.length || 0}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool("get_workouts_count", {}, async () => {
      try {
        const result = await this.client.getWorkoutsCount();

        return {
          content: [
            {
              type: "text",
              text: `Total workouts: ${result.workout_count}`,
            },
          ],
          structuredContent: { workout_count: result.workout_count },
        };
      } catch (error) {
        return handleError(error);
      }
    });

    this.server.tool(
      "get_workout_events",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 10)")
          .default(5),
        since: z
          .string()
          .optional()
          .describe(
            "Get events since this date (ISO 8601 format, e.g., 2024-01-01T00:00:00Z)",
          ),
      },
      async (args) => {
        try {
          // Validate pagination parameters
          validatePagination(
            args.page,
            args.page_size,
            PAGINATION_LIMITS.WORKOUT_EVENTS,
          );

          // Validate date format if provided
          if (args.since) {
            validateISO8601Date(args.since, "since");
          }

          const params: any = { page: args.page, pageSize: args.page_size };
          if (args.since) params.since = args.since;

          const events = await this.client.getWorkoutEvents(params);

          const eventDetails =
            events.events
              ?.map((event: any, index: number) => {
                if (event.type === "deleted") {
                  return `${index + 1}. DELETED - Workout ID: ${event.id}\n   Deleted at: ${event.deleted_at}`;
                } else {
                  return `${index + 1}. UPDATED - ${event.workout?.title || "Untitled"}\n   Workout ID: ${event.workout?.id}\n   Updated: ${event.workout?.updated_at}`;
                }
              })
              .join("\n") || "No events found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${events.events?.length || 0} workout events (page ${events.page} of ${events.page_count})`,
              },
              {
                type: "text",
                text: eventDetails,
              },
            ],
            structuredContent: {
              page: events.page,
              page_count: events.page_count,
              events: events.events ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    // ============================================
    // ROUTINES
    // ============================================

    this.server.tool(
      "get_routines",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 10)")
          .default(5),
      },
      async ({ page, page_size }) => {
        try {
          // Validate pagination parameters
          validatePagination(page, page_size, PAGINATION_LIMITS.ROUTINES);

          const routines = await this.client.getRoutines({
            page,
            pageSize: page_size,
          });

          const routineDetails =
            routines.routines
              ?.map((routine: any, index: number) => {
                const exerciseCount = routine.exercises?.length || 0;
                return `Routine ${index + 1}: ${routine.title}\n  Exercises: ${exerciseCount}\n  ID: ${routine.id}`;
              })
              .join("\n") || "No routines found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${routines.routines?.length || 0} routines (page ${routines.page} of ${routines.page_count})`,
              },
              {
                type: "text",
                text: routineDetails,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(routines.routines, null, 2)}`,
              },
            ],
            structuredContent: {
              page: routines.page,
              page_count: routines.page_count,
              routines: routines.routines ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_routine",
      {
        routine_id: z.string().describe("The ID of the routine to retrieve"),
      },
      async ({ routine_id }) => {
        try {
          const result = await this.client.getRoutine(routine_id);
          const routine = result.routine;

          if (!routine) {
            return {
              content: [
                {
                  type: "text",
                  text: `No routine found with ID ${routine_id}`,
                },
              ],
              structuredContent: { found: false, routine: null },
            };
          }

          return {
            content: [
              {
                type: "text",
                text: `Routine: ${routine.title}\nID: ${routine.id}\nExercises: ${routine.exercises?.length || 0}`,
              },
              {
                type: "text",
                text: JSON.stringify(routine, null, 2),
              },
            ],
            structuredContent: { found: true, routine },
          };
        } catch (error) {
          if (isNotFoundError(error)) {
            return {
              content: [
                {
                  type: "text",
                  text: `No routine found with ID ${routine_id}`,
                },
              ],
              structuredContent: { found: false, routine: null },
            };
          }
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "create_routine",
      CreateRoutineSchema.shape,
      async (args) => {
        try {
          // Validate routine data including exercises and sets
          validateRoutineData(args);

          const routine = await this.client.createRoutine(
            transformRoutineToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully created routine: ${routine.title}`,
              },
              {
                type: "text",
                text: `Routine ID: ${routine.id}\nExercises: ${routine.exercises?.length || 0}`,
              },
              {
                type: "text",
                text: `\n\nFull routine data:\n${JSON.stringify(routine, null, 2)}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "update_routine",
      {
        routine_id: z.string().describe("The ID of the routine to update"),
        ...UpdateRoutineSchema.shape,
      },
      async (args) => {
        try {
          const { routine_id, ...routineData } = args;

          // Validate routine data including exercises and sets
          validateRoutineData(routineData);

          const routine = await this.client.updateRoutine(
            routine_id,
            transformRoutineToAPI(routineData),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully updated routine: ${routine.title}`,
              },
              {
                type: "text",
                text: `Routine ID: ${routine.id}\nExercises: ${routine.exercises?.length || 0}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    // ============================================
    // EXERCISE TEMPLATES
    // ============================================

    this.server.tool(
      "get_exercise_templates",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 100)")
          .default(20),
      },
      async ({ page, page_size }) => {
        try {
          // Validate pagination parameters with higher limit for templates
          validatePagination(
            page,
            page_size,
            PAGINATION_LIMITS.EXERCISE_TEMPLATES,
          );

          const templates = await this.client.getExerciseTemplates({
            page,
            pageSize: page_size,
          });

          const templateDetails =
            templates.exercise_templates
              ?.map((template: any, index: number) => {
                return `${index + 1}. ${template.title} (${template.type})\n   ID: ${template.id}\n   Primary: ${template.primary_muscle_group}\n   Custom: ${template.is_custom ? "Yes" : "No"}`;
              })
              .join("\n") || "No exercise templates found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${templates.exercise_templates?.length || 0} exercise templates (page ${templates.page} of ${templates.page_count})`,
              },
              {
                type: "text",
                text: templateDetails,
              },
            ],
            structuredContent: {
              page: templates.page,
              page_count: templates.page_count,
              exercise_templates: templates.exercise_templates ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_exercise_template",
      {
        exercise_template_id: z
          .string()
          .describe("The ID of the exercise template"),
      },
      async ({ exercise_template_id }) => {
        try {
          const template =
            await this.client.getExerciseTemplate(exercise_template_id);

          return {
            content: [
              {
                type: "text",
                text: `Exercise: ${template.title}\nType: ${template.type}\nPrimary Muscle: ${template.primary_muscle_group}\nCustom: ${template.is_custom ? "Yes" : "No"}`,
              },
              {
                type: "text",
                text: JSON.stringify(template, null, 2),
              },
            ],
            structuredContent: { found: true, exercise_template: template },
          };
        } catch (error) {
          if (isNotFoundError(error)) {
            return {
              content: [
                {
                  type: "text",
                  text: `No exercise template found with ID ${exercise_template_id}`,
                },
              ],
              structuredContent: { found: false, exercise_template: null },
            };
          }
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "search_exercise_templates",
      {
        query: z
          .string()
          .describe("Text to search for in the exercise title (case-insensitive)"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(50)
          .optional()
          .describe("Maximum number of results (default 20)")
          .default(20),
      },
      async ({ query, limit }) => {
        try {
          const catalog = await this.client.getAllExerciseTemplates();
          const matches = filterExerciseTemplates(catalog, query, limit);

          const list =
            matches
              .map((t, index) => {
                return `${index + 1}. ${t.title} (${t.type})\n   ID: ${t.id}\n   Primary: ${t.primary_muscle_group}${t.is_custom ? " [custom]" : ""}`;
              })
              .join("\n") || "No matching exercise templates found";

          return {
            content: [
              {
                type: "text",
                text: `Found ${matches.length} exercise template(s) matching "${query}" (searched ${catalog.length})`,
              },
              {
                type: "text",
                text: list,
              },
            ],
            structuredContent: {
              query,
              count: matches.length,
              searched: catalog.length,
              exercise_templates: matches,
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "create_exercise_template",
      CreateExerciseTemplateSchema.shape,
      async (args) => {
        try {
          // Validate exercise template data
          validateExerciseTemplate(args);

          const result = await this.client.createExerciseTemplate(
            transformExerciseTemplateToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully created custom exercise template: ${args.title}`,
              },
              {
                type: "text",
                text: `Exercise Template ID: ${result.id}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_exercise_history",
      {
        exercise_template_id: z
          .string()
          .describe("The ID of the exercise template"),
        start_date: z
          .string()
          .optional()
          .describe(
            "Optional start date (ISO 8601 format, e.g., 2024-01-01T00:00:00Z)",
          ),
        end_date: z
          .string()
          .optional()
          .describe(
            "Optional end date (ISO 8601 format, e.g., 2024-12-31T23:59:59Z)",
          ),
      },
      async (args) => {
        try {
          // Validate date formats if provided
          if (args.start_date) {
            validateISO8601Date(args.start_date, "start_date");
          }
          if (args.end_date) {
            validateISO8601Date(args.end_date, "end_date");
          }

          // Validate that end_date is after start_date if both are provided
          if (args.start_date && args.end_date) {
            const start = new Date(args.start_date);
            const end = new Date(args.end_date);
            if (end <= start) {
              throw new ValidationError("end_date must be after start_date");
            }
          }

          const params: any = {};
          if (args.start_date) params.start_date = args.start_date;
          if (args.end_date) params.end_date = args.end_date;

          const history = await this.client.getExerciseHistory(
            args.exercise_template_id,
            params,
          );

          const historyDetails =
            history.exercise_history
              ?.map((entry: any, index: number) => {
                return `${index + 1}. ${entry.workout_title} (${entry.workout_start_time})\n   Weight: ${entry.weight_kg}kg, Reps: ${entry.reps}, RPE: ${entry.rpe || "N/A"}\n   Set Type: ${entry.set_type}`;
              })
              .join("\n") || "No exercise history found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${history.exercise_history?.length || 0} exercise history entries`,
              },
              {
                type: "text",
                text: historyDetails,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(history.exercise_history, null, 2)}`,
              },
            ],
            structuredContent: {
              exercise_history: history.exercise_history ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    // ============================================
    // ROUTINE FOLDERS
    // ============================================

    this.server.tool(
      "get_routine_folders",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 10)")
          .default(10),
      },
      async ({ page, page_size }) => {
        try {
          // Validate pagination parameters
          validatePagination(
            page,
            page_size,
            PAGINATION_LIMITS.ROUTINE_FOLDERS,
          );

          const folders = await this.client.getRoutineFolders({
            page,
            pageSize: page_size,
          });

          const folderDetails =
            folders.routine_folders
              ?.map((folder: any, index: number) => {
                return `${index + 1}. ${folder.title}\n   ID: ${folder.id}\n   Index: ${folder.index}`;
              })
              .join("\n") || "No routine folders found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${folders.routine_folders?.length || 0} routine folders (page ${folders.page} of ${folders.page_count})`,
              },
              {
                type: "text",
                text: folderDetails,
              },
            ],
            structuredContent: {
              page: folders.page,
              page_count: folders.page_count,
              routine_folders: folders.routine_folders ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_routine_folder",
      {
        folder_id: z.string().describe("The ID of the routine folder"),
      },
      async ({ folder_id }) => {
        try {
          const folder = await this.client.getRoutineFolder(folder_id);

          return {
            content: [
              {
                type: "text",
                text: `Folder: ${folder.title}\nID: ${folder.id}\nIndex: ${folder.index}`,
              },
              {
                type: "text",
                text: JSON.stringify(folder, null, 2),
              },
            ],
            structuredContent: { found: true, routine_folder: folder },
          };
        } catch (error) {
          if (isNotFoundError(error)) {
            return {
              content: [
                {
                  type: "text",
                  text: `No routine folder found with ID ${folder_id}`,
                },
              ],
              structuredContent: { found: false, routine_folder: null },
            };
          }
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "create_routine_folder",
      CreateRoutineFolderSchema.shape,
      async (args) => {
        try {
          const folder = await this.client.createRoutineFolder(
            transformRoutineFolderToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully created routine folder: ${folder.title}`,
              },
              {
                type: "text",
                text: `Folder ID: ${folder.id}\nIndex: ${folder.index}`,
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    // ============================================
    // USER
    // ============================================

    this.server.tool("get_user_info", {}, async () => {
      try {
        const result = await this.client.getUserInfo();
        // The API wraps the payload in a `data` object
        const user = result?.data;

        return {
          content: [
            {
              type: "text",
              text: `User: ${user?.name || "Unknown"}\nID: ${user?.id || "N/A"}\nProfile: ${user?.url || "N/A"}`,
            },
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
          structuredContent: {
            ...(user?.id !== undefined ? { id: user.id } : {}),
            ...(user?.name !== undefined ? { name: user.name } : {}),
            ...(user?.url !== undefined ? { url: user.url } : {}),
          },
        };
      } catch (error) {
        return handleError(error);
      }
    });

    // ============================================
    // BODY MEASUREMENTS
    // ============================================

    this.server.tool(
      "get_body_measurements",
      {
        page: z
          .number()
          .optional()
          .describe("Page number (Must be 1 or greater)")
          .default(1),
        page_size: z
          .number()
          .optional()
          .describe("Number of items per page (Max 10)")
          .default(10),
      },
      async ({ page, page_size }) => {
        try {
          validatePagination(
            page,
            page_size,
            PAGINATION_LIMITS.BODY_MEASUREMENTS,
          );

          const measurements = await this.client.getBodyMeasurements({
            page,
            pageSize: page_size,
          });

          const measurementDetails =
            measurements.body_measurements
              ?.map((m: any, index: number) => {
                return `${index + 1}. ${m.date}\n   Weight: ${m.weight_kg ?? "N/A"}kg, Fat: ${m.fat_percent ?? "N/A"}%, Waist: ${m.waist ?? "N/A"}cm`;
              })
              .join("\n") || "No body measurements found";

          return {
            content: [
              {
                type: "text",
                text: `Retrieved ${measurements.body_measurements?.length || 0} body measurements (page ${measurements.page} of ${measurements.page_count})`,
              },
              {
                type: "text",
                text: measurementDetails,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(measurements.body_measurements, null, 2)}`,
              },
            ],
            structuredContent: {
              page: measurements.page,
              page_count: measurements.page_count,
              body_measurements: measurements.body_measurements ?? [],
            },
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_body_measurement",
      {
        date: z
          .string()
          .describe("The date of the body measurement (YYYY-MM-DD, e.g., 2024-08-14)"),
      },
      async ({ date }) => {
        try {
          validateDate(date, "date");

          const measurement = await this.client.getBodyMeasurement(date);

          return {
            content: [
              {
                type: "text",
                text: `Body measurement for ${measurement.date || date}\nWeight: ${measurement.weight_kg ?? "N/A"}kg\nBody fat: ${measurement.fat_percent ?? "N/A"}%\nWaist: ${measurement.waist ?? "N/A"}cm`,
              },
              {
                type: "text",
                text: JSON.stringify(measurement, null, 2),
              },
            ],
            structuredContent: {
              found: true,
              date: measurement.date ?? date,
              measurement,
            },
          };
        } catch (error) {
          if (isNotFoundError(error)) {
            return {
              content: [
                {
                  type: "text",
                  text: `No body measurement found for ${date}`,
                },
              ],
              structuredContent: { found: false, date, measurement: null },
            };
          }
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "create_body_measurement",
      CreateBodyMeasurementSchema.shape,
      async (args) => {
        try {
          validateBodyMeasurement(args, { requireDate: true });

          const result = await this.client.createBodyMeasurement(
            transformBodyMeasurementToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully created body measurement for ${args.date}`,
              },
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "update_body_measurement",
      {
        date: z
          .string()
          .describe("The date of the measurement to update (YYYY-MM-DD, e.g., 2024-08-14)"),
        ...UpdateBodyMeasurementSchema.shape,
      },
      async (args) => {
        try {
          const { date, ...measurementData } = args;

          validateDate(date, "date");
          validateBodyMeasurement(measurementData);

          const result = await this.client.updateBodyMeasurement(
            date,
            transformBodyMeasurementToAPI(measurementData),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully updated body measurement for ${date}`,
              },
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_body_progress",
      {
        weeks: z
          .number()
          .int()
          .min(1)
          .max(52)
          .optional()
          .describe("Number of recent weeks to analyze (1-52)")
          .default(8),
      },
      async ({ weeks }) => {
        try {
          const since = new Date(Date.now() - weeks * 7 * 24 * 60 * 60 * 1000)
            .toISOString()
            .slice(0, 10);

          // Page through body measurements (pageSize max 10), capped for safety.
          // Order isn't guaranteed, so we collect entries and filter by date.
          const MAX_PAGES = 20;
          const pageSize = 10;
          const measurements: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;

          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getBodyMeasurements({ page, pageSize });
            } catch (error) {
              // A 404 means an empty account or a page past the last one.
              if (isNotFoundError(error)) break;
              throw error;
            }
            measurements.push(...(result.body_measurements ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = analyzeBodyProgress(measurements, since);
          const reportParts = [formatBodyProgress(summary, weeks)];
          if (!scannedAllPages) {
            reportParts.push(
              `\n(Note: only the first ${MAX_PAGES} pages were scanned; older measurements may exist.)`,
            );
          }

          return {
            content: [
              {
                type: "text",
                text: reportParts.join("\n"),
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_training_summary",
      {
        weeks: z
          .number()
          .int()
          .min(1)
          .max(52)
          .optional()
          .describe("Number of recent weeks to summarize (1-52)")
          .default(4),
      },
      async ({ weeks }) => {
        try {
          const since = new Date(Date.now() - weeks * 7 * 24 * 60 * 60 * 1000)
            .toISOString()
            .slice(0, 10);

          // Page through workouts (pageSize max 10), capped for safety.
          const MAX_PAGES = 20;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;

          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = analyzeTrainingSummary(workouts, since, weeks);
          const reportParts = [formatTrainingSummary(summary, weeks)];
          if (!scannedAllPages) {
            reportParts.push(
              `\n(Note: only the first ${MAX_PAGES} pages were scanned; older workouts may exist.)`,
            );
          }

          return {
            content: [
              {
                type: "text",
                text: reportParts.join("\n"),
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_progression_deltas",
      {
        workout_id: z
          .string()
          .optional()
          .describe(
            "Workout to analyze as the current session (default: the most recent workout)",
          ),
        history_depth: z
          .number()
          .int()
          .min(1)
          .max(20)
          .optional()
          .describe(
            "Prior occurrences to return per exercise (default 1). When >1, each exercise gets an `occurrences` array (current + priors, most recent first).",
          )
          .default(1),
        max_pages: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(
            "Max workout pages to scan (~10 workouts/page). Default 20; raise for deep history.",
          )
          .default(20),
      },
      async ({ workout_id, history_depth, max_pages }) => {
        try {
          // Page through workouts (pageSize max 10), capped for safety. We need
          // enough history to find each exercise's previous occurrence.
          const MAX_PAGES = max_pages;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;

          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          // Resolve the "current" session.
          let current: any;
          if (workout_id) {
            current = workouts.find((w) => w.id === workout_id);
            if (!current) {
              try {
                current = await this.client.getWorkout(workout_id);
              } catch (error) {
                if (isNotFoundError(error)) {
                  return {
                    content: [
                      {
                        type: "text",
                        text: `No workout found with ID ${workout_id}`,
                      },
                    ],
                    structuredContent: {
                      session: null,
                      exercises: [],
                      scanned_workouts: workouts.length,
                      exercises_without_previous: 0,
                      truncated: !scannedAllPages,
                    },
                  };
                }
                throw error;
              }
            }
          } else {
            current = [...workouts].sort((a, b) => {
              const da = typeof a.start_time === "string" ? a.start_time : "";
              const db = typeof b.start_time === "string" ? b.start_time : "";
              return da < db ? 1 : da > db ? -1 : 0;
            })[0];
          }

          if (!current) {
            return {
              content: [{ type: "text", text: "No workouts found." }],
              structuredContent: {
                session: null,
                exercises: [],
                scanned_workouts: workouts.length,
                exercises_without_previous: 0,
                truncated: !scannedAllPages,
              },
            };
          }

          const currentStart =
            typeof current.start_time === "string" ? current.start_time : "";
          const priors = workouts.filter(
            (w) =>
              w.id !== current.id &&
              (typeof w.start_time === "string" ? w.start_time : "") <
                currentStart,
          );

          const summary = analyzeProgressionDeltas(current, priors, {
            scannedWorkouts: workouts.length,
            truncated: !scannedAllPages,
            historyDepth: history_depth,
          });

          return {
            content: [
              {
                type: "text",
                text: formatProgressionDeltas(summary),
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_window_progression",
      {
        weeks: z
          .number()
          .int()
          .min(1)
          .max(52)
          .optional()
          .describe("Window of recent weeks to review (1-52)")
          .default(1),
        history_depth: z
          .number()
          .int()
          .min(1)
          .max(20)
          .optional()
          .describe(
            "Prior occurrences to return per exercise (default 1). When >1, each exercise gets an `occurrences` array (current + priors, most recent first).",
          )
          .default(1),
        max_pages: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(
            "Max workout pages to scan (~10 workouts/page). Default 20; raise for deep history.",
          )
          .default(20),
      },
      async ({ weeks, history_depth, max_pages }) => {
        try {
          const since = new Date(Date.now() - weeks * 7 * 24 * 60 * 60 * 1000)
            .toISOString()
            .slice(0, 10);

          // Page through workouts (pageSize max 10), capped for safety. We need
          // history beyond the window to resolve each exercise's previous
          // occurrence.
          const MAX_PAGES = max_pages;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;

          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = analyzeWindowProgression(workouts, since, weeks, {
            scannedWorkouts: workouts.length,
            truncated: !scannedAllPages,
            historyDepth: history_depth,
          });

          return {
            content: [
              {
                type: "text",
                text: formatWindowProgression(summary),
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_personal_records",
      {
        exercise_template_id: z
          .string()
          .optional()
          .describe("Restrict to a single exercise template (default: all exercises)"),
        max_pages: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(
            "Max workout pages to scan (~10 workouts/page). Default 20; raise so records aren't limited to the recent window.",
          )
          .default(20),
      },
      async ({ exercise_template_id, max_pages }) => {
        try {
          const MAX_PAGES = max_pages;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;
          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = analyzePersonalRecords(workouts, {
            scannedWorkouts: workouts.length,
            truncated: !scannedAllPages,
            ...(exercise_template_id ? { templateId: exercise_template_id } : {}),
          });

          return {
            content: [
              { type: "text", text: formatPersonalRecords(summary) },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "compare_workouts",
      {
        workout_id_a: z.string().describe("First workout ID"),
        workout_id_b: z.string().describe("Second workout ID"),
      },
      async ({ workout_id_a, workout_id_b }) => {
        try {
          const [a, b] = await Promise.all([
            this.client.getWorkout(workout_id_a),
            this.client.getWorkout(workout_id_b),
          ]);

          const comparison = compareWorkouts(a, b);

          return {
            content: [
              {
                type: "text",
                text: `Comparison ${comparison.a.date} vs ${comparison.b.date}: tonnage ${comparison.a.tonnage_kg} vs ${comparison.b.tonnage_kg}kg (Δ ${comparison.delta.tonnage_kg}); effective sets ${comparison.a.effective_sets} vs ${comparison.b.effective_sets}; exercises in both ${comparison.exercises.in_both.length}, only A ${comparison.exercises.only_in_a.length}, only B ${comparison.exercises.only_in_b.length}.`,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(comparison, null, 2)}`,
              },
            ],
            structuredContent: comparison,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_previous_routine_instance",
      {
        routine_id: z.string().describe("The routine ID to find instances of"),
        before_workout_id: z
          .string()
          .optional()
          .describe(
            "Anchor instance; returns the instance before it (default: the most recent instance)",
          ),
        max_pages: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(
            "Max workout pages to scan (~10 workouts/page). Default 20; raise for deep history.",
          )
          .default(20),
      },
      async ({ routine_id, before_workout_id, max_pages }) => {
        try {
          const MAX_PAGES = max_pages;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;
          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = findPreviousRoutineInstance(workouts, routine_id, {
            scannedWorkouts: workouts.length,
            truncated: !scannedAllPages,
            ...(before_workout_id ? { beforeWorkoutId: before_workout_id } : {}),
          });

          return {
            content: [
              {
                type: "text",
                text: `Routine ${routine_id}: ${summary.total_instances} instance(s) found. Anchor: ${summary.anchor?.workout_id ?? "none"} (${summary.anchor?.date ?? "-"}). Previous: ${summary.previous?.workout_id ?? "none"} (${summary.previous?.date ?? "-"}).`,
              },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool(
      "get_muscle_balance",
      {
        weeks: z
          .number()
          .int()
          .min(1)
          .max(52)
          .optional()
          .describe("Number of recent weeks to include (1-52)")
          .default(4),
        include_secondary: z
          .boolean()
          .optional()
          .describe(
            "When true, also returns a separate by_muscle_group_secondary block (sets/volume where the muscle is a secondary mover). Never summed into primary.",
          )
          .default(false),
        max_pages: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe(
            "Max workout pages to scan (~10 workouts/page). Default 20; raise for deep history.",
          )
          .default(20),
      },
      async ({ weeks, include_secondary, max_pages }) => {
        try {
          const since = new Date(Date.now() - weeks * 7 * 24 * 60 * 60 * 1000)
            .toISOString()
            .slice(0, 10);

          // Catalog maps: template_id -> primary / secondary muscle groups
          // (catalog is cached per session).
          const catalog = await this.client.getAllExerciseTemplates();
          const muscleGroupByTemplate: Record<string, string> = {};
          const secondaryByTemplate: Record<string, string[]> = {};
          for (const template of catalog) {
            const id = (template as any)?.id;
            if (typeof id !== "string") continue;
            if (typeof (template as any)?.primary_muscle_group === "string") {
              muscleGroupByTemplate[id] = (template as any).primary_muscle_group;
            }
            if (Array.isArray((template as any)?.secondary_muscle_groups)) {
              secondaryByTemplate[id] = (
                template as any
              ).secondary_muscle_groups.filter(
                (m: unknown) => typeof m === "string",
              );
            }
          }

          const MAX_PAGES = max_pages;
          const pageSize = 10;
          const workouts: any[] = [];
          let page = 1;
          let pageCount = 1;
          let scannedAllPages = true;
          while (page <= pageCount) {
            if (page > MAX_PAGES) {
              scannedAllPages = false;
              break;
            }
            let result: any;
            try {
              result = await this.client.getWorkouts({ page, pageSize });
            } catch (error) {
              if (isNotFoundError(error)) break;
              throw error;
            }
            workouts.push(...(result.workouts ?? []));
            pageCount = result.page_count ?? page;
            page++;
          }

          const summary = analyzeMuscleBalance(
            workouts,
            muscleGroupByTemplate,
            since,
            {
              truncated: !scannedAllPages,
              ...(include_secondary ? { secondaryByTemplate } : {}),
            },
          );

          const rows =
            summary.by_muscle_group
              .map(
                (g) =>
                  `${g.muscle_group}: ${g.effective_sets} sets, ${g.total_volume_kg}kg, ${g.exercise_count} exercise(s)`,
              )
              .join("\n") || "No mapped exercises in the window";

          return {
            content: [
              {
                type: "text",
                text: `Muscle-group distribution since ${since} (${summary.workouts_counted} workout(s), ${summary.unmapped_exercises} unmapped):`,
              },
              { type: "text", text: rows },
              {
                type: "text",
                text: `\n\nFull data:\n${JSON.stringify(summary, null, 2)}`,
              },
            ],
            structuredContent: summary,
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    // ============================================
    // WEBHOOK SUBSCRIPTION
    // ============================================

    this.server.tool("get_webhook_subscription", {}, async () => {
      try {
        const subscription = await this.client.getWebhookSubscription();

        return {
          content: [
            {
              type: "text",
              text: `Webhook URL: ${subscription?.url || "None"}`,
            },
            {
              type: "text",
              text: JSON.stringify(subscription, null, 2),
            },
          ],
          structuredContent: {
            configured: true,
            ...(subscription?.url !== undefined ? { url: subscription.url } : {}),
            ...(subscription?.auth_token !== undefined
              ? { auth_token: subscription.auth_token }
              : {}),
          },
        };
      } catch (error) {
        if (isNotFoundError(error)) {
          return {
            content: [
              {
                type: "text",
                text: "No webhook subscription is configured.",
              },
            ],
            structuredContent: { configured: false },
          };
        }
        return handleError(error);
      }
    });

    this.server.tool(
      "create_webhook_subscription",
      CreateWebhookSubscriptionSchema.shape,
      async (args) => {
        try {
          validateWebhookSubscription(args);

          const result = await this.client.createWebhookSubscription(
            transformWebhookSubscriptionToAPI(args),
          );

          return {
            content: [
              {
                type: "text",
                text: `✓ Successfully created webhook subscription for ${args.url}`,
              },
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        } catch (error) {
          return handleError(error);
        }
      },
    );

    this.server.tool("delete_webhook_subscription", {}, async () => {
      try {
        await this.client.deleteWebhookSubscription();

        return {
          content: [
            {
              type: "text",
              text: "✓ Successfully deleted webhook subscription",
            },
          ],
        };
      } catch (error) {
        return handleError(error);
      }
    });

    // Attach MCP annotation hints (readOnly/destructive/idempotent/openWorld),
    // descriptions, and output schemas to every registered tool.
    applyToolAnnotations(this.server);
    applyToolDescriptions(this.server);
    applyToolOutputSchemas(this.server);
  }
}
