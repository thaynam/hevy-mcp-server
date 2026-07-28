import { BODY_MEASUREMENT_METRIC_FIELDS } from "./transforms.js";

/**
 * Body-progress analysis.
 *
 * Composite/aggregation helpers that turn a list of raw body measurements into
 * a trend summary over a time window. Kept as pure functions (no I/O) so the
 * math is easy to test; the tool handler does the paging and passes the raw
 * entries in.
 */

/** Trend for a single measurement metric over the analyzed window. */
export interface MetricTrend {
	/** Measurement field name, e.g. "weight_kg". */
	field: string;
	/** Value at the earliest dated entry that has this metric. */
	first: number;
	/** Value at the latest dated entry that has this metric. */
	last: number;
	/** last - first (rounded to 2dp). Negative = decreased over the window. */
	change: number;
	/** Number of entries in the window that recorded this metric. */
	count: number;
	/** Date (YYYY-MM-DD) of the first data point. */
	firstDate: string;
	/** Date (YYYY-MM-DD) of the last data point. */
	lastDate: string;
}

/** Summary of body-measurement trends over a window. */
export interface BodyProgressSummary {
	/** Inclusive lower bound of the window (YYYY-MM-DD). */
	since: string;
	/** Number of measurement entries that fell within the window. */
	entryCount: number;
	/** Earliest entry date in the window, if any. */
	firstDate?: string;
	/** Latest entry date in the window, if any. */
	lastDate?: string;
	/** Per-metric trends, only for metrics with at least one data point. */
	metrics: MetricTrend[];
}

type MeasurementLike = Record<string, unknown> & { date?: unknown };

function roundTo2(value: number): number {
	return Math.round(value * 100) / 100;
}

/**
 * Computes per-metric trends for the measurements dated on/after `since`.
 *
 * Dates are YYYY-MM-DD, so lexicographic comparison is chronological. Entries
 * are sorted ascending by date; for each metric, `first`/`last` come from the
 * earliest/latest entries that actually recorded a (numeric) value for it.
 *
 * @param measurements - Raw body measurement entries (any order)
 * @param since - Inclusive lower-bound date (YYYY-MM-DD)
 */
export function analyzeBodyProgress(
	measurements: MeasurementLike[],
	since: string,
): BodyProgressSummary {
	const inWindow = measurements
		.filter((m) => typeof m.date === "string" && (m.date as string) >= since)
		.sort((a, b) =>
			(a.date as string) < (b.date as string)
				? -1
				: (a.date as string) > (b.date as string)
					? 1
					: 0,
		);

	const metrics: MetricTrend[] = [];
	for (const field of BODY_MEASUREMENT_METRIC_FIELDS) {
		const points = inWindow.filter((m) => typeof m[field] === "number");
		if (points.length === 0) continue;

		const firstPoint = points[0];
		const lastPoint = points[points.length - 1];
		const first = firstPoint[field] as number;
		const last = lastPoint[field] as number;

		metrics.push({
			field,
			first,
			last,
			change: roundTo2(last - first),
			count: points.length,
			firstDate: firstPoint.date as string,
			lastDate: lastPoint.date as string,
		});
	}

	const summary: BodyProgressSummary = {
		since,
		entryCount: inWindow.length,
		metrics,
	};
	if (inWindow.length > 0) {
		summary.firstDate = inWindow[0].date as string;
		summary.lastDate = inWindow[inWindow.length - 1].date as string;
	}
	return summary;
}

/**
 * Renders a body-progress summary as a compact human-readable report.
 */
export function formatBodyProgress(
	summary: BodyProgressSummary,
	weeks: number,
): string {
	if (summary.entryCount === 0) {
		return `No body measurements logged in the last ${weeks} week(s) (since ${summary.since}).`;
	}

	const lines: string[] = [];
	lines.push(
		`Body progress over the last ${weeks} week(s) (since ${summary.since}):`,
	);
	lines.push(
		`${summary.entryCount} measurement(s) from ${summary.firstDate} to ${summary.lastDate}.`,
	);

	if (summary.metrics.length === 0) {
		lines.push("No numeric metrics were recorded in this window.");
		return lines.join("\n");
	}

	lines.push("");
	for (const m of summary.metrics) {
		const arrow = m.change < 0 ? "▼" : m.change > 0 ? "▲" : "=";
		const sign = m.change > 0 ? "+" : "";
		lines.push(
			`${m.field}: ${m.first} → ${m.last} (${arrow} ${sign}${m.change}) over ${m.count} entr${m.count === 1 ? "y" : "ies"}`,
		);
	}

	return lines.join("\n");
}

/** Summary of training activity over a window. */
export interface TrainingSummary {
	/** Inclusive lower bound of the window (YYYY-MM-DD). */
	since: string;
	/** Number of workouts logged in the window. */
	workoutCount: number;
	/** Distinct calendar days with at least one workout. */
	activeDays: number;
	/** Total number of exercises across the window's workouts. */
	totalExercises: number;
	/** Total number of sets across the window's workouts. */
	totalSets: number;
	/** Total training volume (sum of weight_kg × reps) in kilograms. */
	totalVolumeKg: number;
	/** Average workouts per week over the window. */
	avgWorkoutsPerWeek: number;
	/** Date (YYYY-MM-DD) of the earliest workout in the window, if any. */
	firstDate?: string;
	/** Date (YYYY-MM-DD) of the latest workout in the window, if any. */
	lastDate?: string;
}

type WorkoutLike = Record<string, unknown> & { start_time?: unknown };

function workoutDate(workout: WorkoutLike): string | undefined {
	return typeof workout.start_time === "string"
		? workout.start_time.slice(0, 10)
		: undefined;
}

/**
 * Aggregates training activity (workouts, sets, volume) for workouts dated
 * on/after `since`.
 *
 * Volume counts a set only when both weight_kg and reps are numeric.
 *
 * @param workouts - Raw workout entries (any order)
 * @param since - Inclusive lower-bound date (YYYY-MM-DD)
 * @param weeks - Window length, used for the per-week average
 */
export function analyzeTrainingSummary(
	workouts: WorkoutLike[],
	since: string,
	weeks: number,
): TrainingSummary {
	const inWindow = workouts
		.filter((w) => {
			const date = workoutDate(w);
			return date !== undefined && date >= since;
		})
		.sort((a, b) => {
			const da = workoutDate(a) ?? "";
			const db = workoutDate(b) ?? "";
			return da < db ? -1 : da > db ? 1 : 0;
		});

	const activeDays = new Set<string>();
	let totalExercises = 0;
	let totalSets = 0;
	let totalVolumeKg = 0;

	for (const workout of inWindow) {
		const date = workoutDate(workout);
		if (date) activeDays.add(date);

		const exercises = Array.isArray(workout.exercises) ? workout.exercises : [];
		totalExercises += exercises.length;

		for (const exercise of exercises) {
			const sets = Array.isArray(exercise?.sets) ? exercise.sets : [];
			totalSets += sets.length;
			for (const set of sets) {
				if (
					typeof set?.weight_kg === "number" &&
					typeof set?.reps === "number"
				) {
					totalVolumeKg += set.weight_kg * set.reps;
				}
			}
		}
	}

	const summary: TrainingSummary = {
		since,
		workoutCount: inWindow.length,
		activeDays: activeDays.size,
		totalExercises,
		totalSets,
		totalVolumeKg: roundTo2(totalVolumeKg),
		avgWorkoutsPerWeek: roundTo2(inWindow.length / Math.max(weeks, 1)),
	};
	if (inWindow.length > 0) {
		const first = workoutDate(inWindow[0]);
		const last = workoutDate(inWindow[inWindow.length - 1]);
		if (first !== undefined) summary.firstDate = first;
		if (last !== undefined) summary.lastDate = last;
	}
	return summary;
}

/**
 * Renders a training summary as a compact human-readable report.
 */
export function formatTrainingSummary(
	summary: TrainingSummary,
	weeks: number,
): string {
	if (summary.workoutCount === 0) {
		return `No workouts logged in the last ${weeks} week(s) (since ${summary.since}).`;
	}

	return [
		`Training summary over the last ${weeks} week(s) (since ${summary.since}):`,
		`Workouts: ${summary.workoutCount} (${summary.avgWorkoutsPerWeek}/week, ${summary.activeDays} active day(s))`,
		`From ${summary.firstDate} to ${summary.lastDate}.`,
		`Exercises: ${summary.totalExercises} | Sets: ${summary.totalSets} | Volume: ${summary.totalVolumeKg} kg`,
	].join("\n");
}
