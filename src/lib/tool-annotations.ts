import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

/**
 * MCP tool annotation hints for the Hevy tools.
 *
 * Annotations are advisory hints (per the MCP spec) that help clients and
 * safety UIs reason about a tool without calling it — e.g. whether it mutates
 * data. Every Hevy tool operates only on the authenticated user's own data in
 * a closed, fully-specified API, so `openWorldHint` is always false.
 */

// All Hevy tools talk to the same closed, single-user API surface.
const CLOSED_WORLD = { openWorldHint: false } as const;

/** Read-only tools (get_*): no side effects. */
export function readOnlyAnnotations(title: string): ToolAnnotations {
	return { title, readOnlyHint: true, ...CLOSED_WORLD };
}

/** Create tools (create_*): additive writes; repeating creates duplicates. */
export function createAnnotations(title: string): ToolAnnotations {
	return {
		title,
		readOnlyHint: false,
		destructiveHint: false,
		idempotentHint: false,
		...CLOSED_WORLD,
	};
}

/** Update tools (update_*): PUT-style overwrites, so destructive but idempotent. */
export function updateAnnotations(title: string): ToolAnnotations {
	return {
		title,
		readOnlyHint: false,
		destructiveHint: true,
		idempotentHint: true,
		...CLOSED_WORLD,
	};
}

/** Delete tools (delete_*): destructive and idempotent. */
export function destructiveAnnotations(title: string): ToolAnnotations {
	return {
		title,
		readOnlyHint: false,
		destructiveHint: true,
		idempotentHint: true,
		...CLOSED_WORLD,
	};
}

/**
 * Annotation hints keyed by tool name. Keep in sync with the tools registered
 * in `mcp-agent.ts`.
 */
export const HEVY_TOOL_ANNOTATIONS: Record<string, ToolAnnotations> = {
	// Workouts
	get_workouts: readOnlyAnnotations("Get Workouts"),
	get_workout: readOnlyAnnotations("Get Workout"),
	create_workout: createAnnotations("Create Workout"),
	update_workout: updateAnnotations("Update Workout"),
	get_workouts_count: readOnlyAnnotations("Get Workouts Count"),
	get_workout_events: readOnlyAnnotations("Get Workout Events"),
	// Routines
	get_routines: readOnlyAnnotations("Get Routines"),
	get_routine: readOnlyAnnotations("Get Routine"),
	create_routine: createAnnotations("Create Routine"),
	update_routine: updateAnnotations("Update Routine"),
	// Exercise templates / history
	get_exercise_templates: readOnlyAnnotations("Get Exercise Templates"),
	get_exercise_template: readOnlyAnnotations("Get Exercise Template"),
	create_exercise_template: createAnnotations("Create Exercise Template"),
	get_exercise_history: readOnlyAnnotations("Get Exercise History"),
	// Routine folders
	get_routine_folders: readOnlyAnnotations("Get Routine Folders"),
	get_routine_folder: readOnlyAnnotations("Get Routine Folder"),
	create_routine_folder: createAnnotations("Create Routine Folder"),
	// User
	get_user_info: readOnlyAnnotations("Get User Info"),
	// Body measurements
	get_body_measurements: readOnlyAnnotations("Get Body Measurements"),
	get_body_measurement: readOnlyAnnotations("Get Body Measurement"),
	create_body_measurement: createAnnotations("Create Body Measurement"),
	update_body_measurement: updateAnnotations("Update Body Measurement"),
	get_body_progress: readOnlyAnnotations("Get Body Progress"),
	get_training_summary: readOnlyAnnotations("Get Training Summary"),
	// Webhook subscription
	get_webhook_subscription: readOnlyAnnotations("Get Webhook Subscription"),
	create_webhook_subscription: createAnnotations("Create Webhook Subscription"),
	delete_webhook_subscription: destructiveAnnotations("Delete Webhook Subscription"),
};

/**
 * Applies the annotation hints to already-registered tools.
 *
 * We attach annotations after registration via the server's internal tool
 * registry instead of threading them through every `server.tool(...)` call
 * site. `tools/list` reads `annotations` live from this registry, and
 * annotations are hints only, so this cannot change tool behavior.
 */
export function applyToolAnnotations(server: McpServer): void {
	const registry = (
		server as unknown as {
			_registeredTools?: Record<string, { annotations?: ToolAnnotations }>;
		}
	)._registeredTools;

	if (!registry) return;

	for (const [name, annotations] of Object.entries(HEVY_TOOL_ANNOTATIONS)) {
		const tool = registry[name];
		if (tool) {
			tool.annotations = annotations;
		}
	}
}
