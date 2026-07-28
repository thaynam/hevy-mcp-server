import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Human/LLM-facing descriptions for the Hevy tools.
 *
 * Our tools are registered with the 3-arg `server.tool(name, shape, handler)`
 * form, which sets no description. Good descriptions materially improve tool
 * selection across MCP clients (Claude and others), so we attach them here —
 * following a small, consistent shape: what the tool does, when to use it, and
 * any gotcha worth calling out.
 */

interface ToolDescription {
	/** One line: read-only vs. writes, and what it operates on. */
	summary: string;
	/** When to reach for this tool vs. a neighbouring one. */
	useCase?: string;
	/** A single important caveat (limits, formats, side effects). */
	note?: string;
}

/** Formats a structured description into a single description string. */
export function describeTool(d: ToolDescription): string {
	return [d.summary, d.useCase, d.note ? `Note: ${d.note}` : undefined]
		.filter(Boolean)
		.join(" ");
}

/** Descriptions keyed by tool name. Keep in sync with `mcp-agent.ts`. */
export const HEVY_TOOL_DESCRIPTIONS: Record<string, string> = {
	// Workouts
	get_workouts: describeTool({
		summary: "Read-only. Lists the account's workouts, most recent first, paginated.",
		useCase:
			"Use to browse workout history or find a workout's ID; use get_workout for full detail on one.",
		note: "page starts at 1; pageSize max 10.",
	}),
	get_workout: describeTool({
		summary:
			"Read-only. Returns one workout by ID, including its exercises and sets.",
		useCase: "Use when the workout ID is known (e.g. from get_workouts).",
	}),
	create_workout: describeTool({
		summary: "Writes a new completed workout to the Hevy account.",
		useCase: "Use to log a finished session with its exercises and sets.",
		note: "start_time and end_time are ISO 8601; at least one exercise is required.",
	}),
	update_workout: describeTool({
		summary: "Overwrites an existing workout (by ID) with the provided data.",
		useCase: "Use to correct or edit a logged workout.",
		note: "replaces prior content, so send the full workout.",
	}),
	get_workouts_count: describeTool({
		summary: "Read-only. Returns the total number of workouts on the account.",
		useCase: "Use for totals or streaks without paging through workouts.",
	}),
	get_workout_events: describeTool({
		summary:
			"Read-only. Lists workout change events (updated/deleted) since a date, paginated.",
		useCase: "Use to sync local state incrementally.",
		note: "pass `since` (ISO 8601) to get only recent changes.",
	}),
	// Routines
	get_routines: describeTool({
		summary: "Read-only. Lists saved routines (workout templates), paginated.",
		useCase:
			"Use to browse routines or find a routine's ID; use get_routine for full detail.",
	}),
	get_routine: describeTool({
		summary:
			"Read-only. Returns one routine by ID with its exercises and target sets.",
		useCase: "Use when the routine ID is known.",
	}),
	create_routine: describeTool({
		summary: "Creates a new routine (a reusable workout template).",
		useCase: "Use to save a planned workout; optionally place it in a folder via folder_id.",
	}),
	update_routine: describeTool({
		summary: "Overwrites an existing routine (by ID).",
		useCase: "Use to edit a routine's exercises or targets.",
		note: "replaces prior content, so send the full routine.",
	}),
	// Exercise templates / history
	get_exercise_templates: describeTool({
		summary:
			"Read-only. Lists exercise templates (the exercise catalog), paginated.",
		useCase:
			"Use to find an exercise_template_id needed by workouts and routines.",
		note: "pageSize max 100.",
	}),
	get_exercise_template: describeTool({
		summary:
			"Read-only. Returns one exercise template by ID (type, muscle groups, equipment).",
		useCase: "Use when the template ID is known.",
	}),
	search_exercise_templates: describeTool({
		summary:
			"Read-only. Searches the exercise catalog by name and returns matching templates with their IDs.",
		useCase:
			"Use to find an exercise_template_id from a name (e.g. 'bench press') to build a workout/routine, instead of paging get_exercise_templates.",
		note: "case-insensitive title match; limit defaults to 20. The catalog is cached per session.",
	}),
	create_exercise_template: describeTool({
		summary: "Creates a custom exercise template on the account.",
		useCase: "Use when an exercise isn't in Hevy's catalog.",
		note: "subject to Hevy's custom-exercise limit.",
	}),
	get_exercise_history: describeTool({
		summary:
			"Read-only. Returns logged history (weights, reps, RPE) for one exercise template.",
		useCase: "Use to analyze progress on a specific exercise, optionally within a date range.",
	}),
	// Routine folders
	get_routine_folders: describeTool({
		summary: "Read-only. Lists routine folders, paginated.",
		useCase: "Use to browse folders or find a folder ID for organizing routines.",
	}),
	get_routine_folder: describeTool({
		summary: "Read-only. Returns one routine folder by ID.",
		useCase: "Use when the folder ID is known.",
	}),
	create_routine_folder: describeTool({
		summary: "Creates a new routine folder for organizing routines.",
	}),
	// User
	get_user_info: describeTool({
		summary:
			"Read-only. Returns the authenticated user's profile (id, name, public profile URL).",
		useCase: "Use to identify whose data this is.",
	}),
	// Body measurements
	get_body_measurements: describeTool({
		summary:
			"Read-only. Lists dated body measurements (weight, body-fat, circumferences), most recent first, paginated.",
		useCase:
			"Use to browse measurement history or trends; use get_body_measurement for one date.",
		note: "pageSize max 10.",
	}),
	get_body_measurement: describeTool({
		summary:
			"Read-only. Returns the body measurement logged for one date (YYYY-MM-DD).",
		useCase: "Use when the exact date is known; at most one entry exists per date.",
		note: "returns a clean 'not found' if nothing is logged for that date.",
	}),
	create_body_measurement: describeTool({
		summary: "Logs a body measurement for a date (YYYY-MM-DD).",
		useCase: "Use for a date with no entry; include at least one metric (e.g. weight_kg).",
		note: "date must be unique — returns 409 if an entry already exists.",
	}),
	update_body_measurement: describeTool({
		summary:
			"Updates the body measurement for an existing date (YYYY-MM-DD).",
		useCase: "Use to correct a logged entry.",
		note: "the date must already exist (404 otherwise).",
	}),
	get_body_progress: describeTool({
		summary:
			"Read-only. Summarizes body-measurement trends (weight, body-fat, circumferences) over the last N weeks.",
		useCase:
			"Use to see progress/direction at a glance instead of paging through get_body_measurements; each metric reports first → last, change, and count.",
		note: "weeks defaults to 8 (1-52); scans the account's recent measurements.",
	}),
	get_training_summary: describeTool({
		summary:
			"Read-only. Summarizes training activity (workouts, sets, volume, frequency) over the last N weeks.",
		useCase:
			"Use for a training-load/consistency overview instead of paging through get_workouts; reports workout count, per-week average, active days, total sets and volume (kg).",
		note: "weeks defaults to 4 (1-52); scans the account's recent workouts.",
	}),
	// Webhook subscription
	get_webhook_subscription: describeTool({
		summary:
			"Read-only. Returns the current webhook subscription (URL + auth token).",
		useCase: "Use to check whether workout-created webhooks are configured.",
		note: "returns a clean 'not configured' message when none exists.",
	}),
	create_webhook_subscription: describeTool({
		summary:
			"Registers a webhook URL that Hevy POSTs to when a workout is created.",
		useCase:
			"Provide the URL and an optional auth_token sent as the Authorization header.",
		note: "replaces any existing subscription.",
	}),
	delete_webhook_subscription: describeTool({
		summary: "Deletes the current webhook subscription.",
		note: "safe to call even if none exists.",
	}),
};

/**
 * Attaches descriptions to already-registered tools via the server's internal
 * registry (which `tools/list` reads live), so we don't have to thread a
 * description argument through every registration call site.
 */
export function applyToolDescriptions(server: McpServer): void {
	const registry = (
		server as unknown as {
			_registeredTools?: Record<string, { description?: string }>;
		}
	)._registeredTools;

	if (!registry) return;

	for (const [name, description] of Object.entries(HEVY_TOOL_DESCRIPTIONS)) {
		const tool = registry[name];
		if (tool) {
			tool.description = description;
		}
	}
}
