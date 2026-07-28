import type { components, paths } from "../generated/hevy-api.js";

/**
 * Convenience type aliases over the OpenAPI-generated types
 * (`src/generated/hevy-api.ts`, produced from `api.json` via
 * `npm run generate:types`). These give the hand-written client real return
 * types without a runtime dependency — the generated types are erased at build.
 */

export type Schemas = components["schemas"];

// ── Entities ────────────────────────────────────────────────────────────────
export type Workout = Schemas["Workout"];
export type Routine = Schemas["Routine"];
export type ExerciseTemplate = Schemas["ExerciseTemplate"];
export type RoutineFolder = Schemas["RoutineFolder"];
export type BodyMeasurement = Schemas["BodyMeasurement"];
export type PutBodyMeasurement = Schemas["PutBodyMeasurement"];
export type ExerciseHistoryEntry = Schemas["ExerciseHistoryEntry"];
export type UserInfoResponse = Schemas["UserInfoResponse"];

// ── Request bodies ──────────────────────────────────────────────────────────
export type PostWorkoutsRequestBody = Schemas["PostWorkoutsRequestBody"];
export type PostRoutinesRequestBody = Schemas["PostRoutinesRequestBody"];
export type PutRoutinesRequestBody = Schemas["PutRoutinesRequestBody"];
export type PostRoutineFolderRequestBody = Schemas["PostRoutineFolderRequestBody"];
export type CreateCustomExerciseRequestBody =
	Schemas["CreateCustomExerciseRequestBody"];
export type WebhookRequestBody = Schemas["WebhookRequestBody"];

// ── Response helpers ────────────────────────────────────────────────────────
/** Extracts the 200 `application/json` response body from a path operation. */
type OkJson<T> = T extends {
	responses: { 200: { content: { "application/json": infer B } } };
}
	? B
	: never;

export type WorkoutsListResponse = OkJson<paths["/v1/workouts"]["get"]>;
export type WorkoutResponse = OkJson<paths["/v1/workouts/{workoutId}"]["get"]>;
export type WorkoutsCountResponse = OkJson<paths["/v1/workouts/count"]["get"]>;
export type WorkoutEventsResponse = OkJson<paths["/v1/workouts/events"]["get"]>;
export type RoutinesListResponse = OkJson<paths["/v1/routines"]["get"]>;
export type RoutineResponse = OkJson<paths["/v1/routines/{routineId}"]["get"]>;
export type ExerciseTemplatesListResponse = OkJson<
	paths["/v1/exercise_templates"]["get"]
>;
export type ExerciseTemplateResponse = OkJson<
	paths["/v1/exercise_templates/{exerciseTemplateId}"]["get"]
>;
export type ExerciseHistoryResponse = OkJson<
	paths["/v1/exercise_history/{exerciseTemplateId}"]["get"]
>;
export type RoutineFoldersListResponse = OkJson<
	paths["/v1/routine_folders"]["get"]
>;
export type RoutineFolderResponse = OkJson<
	paths["/v1/routine_folders/{folderId}"]["get"]
>;
export type BodyMeasurementsListResponse = OkJson<
	paths["/v1/body_measurements"]["get"]
>;
export type BodyMeasurementResponse = OkJson<
	paths["/v1/body_measurements/{date}"]["get"]
>;
export type UserInfoResp = OkJson<paths["/v1/user/info"]["get"]>;
export type WebhookSubscriptionResponse = OkJson<
	paths["/v1/webhook-subscription"]["get"]
>;
