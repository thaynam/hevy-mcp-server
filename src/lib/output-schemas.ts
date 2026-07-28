import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BODY_MEASUREMENT_METRIC_FIELDS } from "./transforms.js";

/**
 * MCP tool output schemas (structured content).
 *
 * Declaring an `outputSchema` lets read tools return typed `structuredContent`
 * alongside their human-readable text, so an MCP client (Claude, and machine
 * consumers like FitCrew) can parse fields directly instead of scraping text.
 *
 * The MCP SDK enforces this: a tool with an output schema MUST return
 * `structuredContent` matching the schema on every successful (non-error)
 * result. We therefore attach schemas only to reads whose handlers set
 * `structuredContent`. Schemas are attached post-registration via the same
 * live tool registry used for annotations/descriptions — the SDK's
 * `normalizeObjectSchema` accepts a raw Zod shape directly.
 */

// A body measurement as returned by the API: a date plus nullable metrics.
const measurementMetricFields = Object.fromEntries(
	BODY_MEASUREMENT_METRIC_FIELDS.map((field) => [
		field,
		z.number().nullable().optional(),
	]),
) as Record<string, z.ZodTypeAny>;

const measurementObject = z.object({
	date: z.string().optional(),
	...measurementMetricFields,
});

const metricTrendObject = z.object({
	field: z.string(),
	first: z.number(),
	last: z.number(),
	change: z.number(),
	count: z.number(),
	firstDate: z.string(),
	lastDate: z.string(),
});

/** Output schemas (raw Zod shapes) keyed by tool name. */
export const HEVY_TOOL_OUTPUT_SCHEMAS: Record<string, z.ZodRawShape> = {
	get_workouts_count: {
		workout_count: z.number(),
	},
	get_user_info: {
		id: z.string().optional(),
		name: z.string().optional(),
		url: z.string().optional(),
	},
	get_body_measurements: {
		page: z.number().optional(),
		page_count: z.number().optional(),
		body_measurements: z.array(measurementObject),
	},
	get_body_measurement: {
		found: z.boolean(),
		date: z.string(),
		measurement: measurementObject.nullable(),
	},
	get_body_progress: {
		since: z.string(),
		entryCount: z.number(),
		firstDate: z.string().optional(),
		lastDate: z.string().optional(),
		metrics: z.array(metricTrendObject),
	},
	get_training_summary: {
		since: z.string(),
		workoutCount: z.number(),
		activeDays: z.number(),
		totalExercises: z.number(),
		totalSets: z.number(),
		totalVolumeKg: z.number(),
		avgWorkoutsPerWeek: z.number(),
		firstDate: z.string().optional(),
		lastDate: z.string().optional(),
	},
};

/**
 * Attaches output schemas to already-registered tools via the server's internal
 * registry. The SDK reads `tool.outputSchema` (a raw shape is accepted) at both
 * tools/list and result-validation time.
 */
export function applyToolOutputSchemas(server: McpServer): void {
	const registry = (
		server as unknown as {
			_registeredTools?: Record<string, { outputSchema?: z.ZodRawShape }>;
		}
	)._registeredTools;

	if (!registry) return;

	for (const [name, shape] of Object.entries(HEVY_TOOL_OUTPUT_SCHEMAS)) {
		const tool = registry[name];
		if (tool) {
			tool.outputSchema = shape;
		}
	}
}
