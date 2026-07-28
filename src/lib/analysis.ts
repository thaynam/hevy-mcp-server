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
		// Facts only: signed change, no directional/judgment arrows.
		const sign = m.change > 0 ? "+" : "";
		lines.push(
			`${m.field}: ${m.first} → ${m.last} (change ${sign}${m.change}) over ${m.count} entr${m.count === 1 ? "y" : "ies"}`,
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
	/** Number of effective (non-warmup) sets across the window's workouts. */
	effectiveSets: number;
	/** Training volume (sum of weight_kg × reps) over effective sets, in kg. */
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
 * Aggregates training activity (workouts, effective sets, volume) for workouts
 * dated on/after `since`. Warmup sets are excluded from set and volume counts.
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
	let effectiveSets = 0;
	let totalVolumeKg = 0;

	for (const workout of inWindow) {
		const date = workoutDate(workout);
		if (date) activeDays.add(date);

		const exercises = Array.isArray(workout.exercises) ? workout.exercises : [];
		totalExercises += exercises.length;

		for (const exercise of exercises) {
			const sets = Array.isArray(exercise?.sets) ? exercise.sets : [];
			const effective = sets.filter(isEffectiveSet);
			effectiveSets += effective.length;
			for (const set of effective) {
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
		effectiveSets,
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
		`Exercises: ${summary.totalExercises} | Effective sets: ${summary.effectiveSets} | Volume: ${summary.totalVolumeKg} kg`,
	].join("\n");
}

// ── Progression deltas ──────────────────────────────────────────────────────
//
// Fact-only diff: for each exercise in a session, the raw metrics of the current
// occurrence vs. the previous occurrence of the SAME exercise_template_id. No
// classification (good/bad/plateau) — the consumer owns judgment, because the
// same delta means opposite things depending on the user's phase (cut/bulk).
// Warmup sets are excluded from every aggregation.

/** The heaviest effective (non-warmup) set of an exercise occurrence. */
export interface ProgressionTopSet {
	weight_kg: number;
	reps: number | null;
	rpe: number | null;
}

/** Fact-only metrics for one occurrence of an exercise. */
export interface ExerciseOccurrence {
	workout_id: string;
	date: string;
	/** Count of non-warmup sets. */
	effective_sets: number;
	/** Sum of weight_kg × reps over effective sets. */
	total_volume_kg: number;
	/** Sum of reps over effective sets. */
	total_reps: number;
	max_weight_kg: number | null;
	/** Best Epley estimate (weight × (1 + reps/30)) over effective sets. */
	best_estimated_1rm_kg: number | null;
	top_set: ProgressionTopSet | null;
}

/** Raw arithmetic difference (current − previous) per comparable field. */
export interface ProgressionDelta {
	effective_sets: number;
	total_volume_kg: number;
	total_reps: number;
	max_weight_kg: number | null;
	best_estimated_1rm_kg: number | null;
	top_set_weight_kg: number | null;
	top_set_reps: number | null;
}

export interface ExerciseProgression {
	exercise_template_id: string;
	exercise_title?: string;
	current: ExerciseOccurrence;
	previous: ExerciseOccurrence | null;
	delta: ProgressionDelta | null;
}

export interface ProgressionDeltasResult {
	session: { workout_id: string; date: string; exercise_count: number } | null;
	exercises: ExerciseProgression[];
	scanned_workouts: number;
	exercises_without_previous: number;
	truncated: boolean;
}

function isEffectiveSet(set: any): boolean {
	// Only explicit warmup sets are excluded; every other type counts.
	return set?.type !== "warmup";
}

function numeric(value: unknown): number | null {
	return typeof value === "number" && !Number.isNaN(value) ? value : null;
}

/** Epley estimate; null unless both weight and reps are present and positive. */
function estimatedOneRepMax(
	weight: number | null,
	reps: number | null,
): number | null {
	if (weight === null || reps === null || weight <= 0 || reps <= 0) return null;
	return weight * (1 + reps / 30);
}

function workoutStart(workout: any): string {
	return typeof workout?.start_time === "string" ? workout.start_time : "";
}

/** Computes the fact-only metrics for one exercise occurrence (warmup excluded). */
export function computeExerciseOccurrence(
	exercise: any,
	workoutId: string,
	date: string,
): ExerciseOccurrence {
	const sets: any[] = Array.isArray(exercise?.sets) ? exercise.sets : [];
	const effective = sets.filter(isEffectiveSet);

	let totalVolume = 0;
	let totalReps = 0;
	let maxWeight: number | null = null;
	let best1rm: number | null = null;
	let topSet: ProgressionTopSet | null = null;

	for (const set of effective) {
		const weight = numeric(set?.weight_kg);
		const reps = numeric(set?.reps);
		const rpe = numeric(set?.rpe);

		if (weight !== null && reps !== null) totalVolume += weight * reps;
		if (reps !== null) totalReps += reps;

		if (weight !== null) {
			if (maxWeight === null || weight > maxWeight) maxWeight = weight;

			const isHeavier =
				topSet === null ||
				weight > topSet.weight_kg ||
				(weight === topSet.weight_kg && (reps ?? 0) > (topSet.reps ?? 0));
			if (isHeavier) topSet = { weight_kg: weight, reps, rpe };
		}

		const e1rm = estimatedOneRepMax(weight, reps);
		if (e1rm !== null && (best1rm === null || e1rm > best1rm)) best1rm = e1rm;
	}

	return {
		workout_id: workoutId,
		date,
		effective_sets: effective.length,
		total_volume_kg: roundTo2(totalVolume),
		total_reps: totalReps,
		max_weight_kg: maxWeight,
		best_estimated_1rm_kg: best1rm !== null ? roundTo2(best1rm) : null,
		top_set: topSet,
	};
}

function subtractNullable(a: number | null, b: number | null): number | null {
	return a !== null && b !== null ? roundTo2(a - b) : null;
}

function computeProgressionDelta(
	current: ExerciseOccurrence,
	previous: ExerciseOccurrence,
): ProgressionDelta {
	return {
		effective_sets: current.effective_sets - previous.effective_sets,
		total_volume_kg: roundTo2(current.total_volume_kg - previous.total_volume_kg),
		total_reps: current.total_reps - previous.total_reps,
		max_weight_kg: subtractNullable(current.max_weight_kg, previous.max_weight_kg),
		best_estimated_1rm_kg: subtractNullable(
			current.best_estimated_1rm_kg,
			previous.best_estimated_1rm_kg,
		),
		top_set_weight_kg: subtractNullable(
			current.top_set?.weight_kg ?? null,
			previous.top_set?.weight_kg ?? null,
		),
		top_set_reps: subtractNullable(
			current.top_set?.reps ?? null,
			previous.top_set?.reps ?? null,
		),
	};
}

/**
 * For each exercise in the current session, finds the previous occurrence of the
 * same exercise_template_id among earlier workouts and returns the raw diff.
 *
 * @param currentWorkout - The session to analyze
 * @param priorWorkouts - Earlier workouts (any order); matched by template_id
 * @param options.scannedWorkouts - How many workouts the caller scanned
 * @param options.truncated - Whether the caller hit its scan cap
 */
export function analyzeProgressionDeltas(
	currentWorkout: any,
	priorWorkouts: any[],
	options: { scannedWorkouts: number; truncated: boolean },
): ProgressionDeltasResult {
	const currentId =
		typeof currentWorkout?.id === "string" ? currentWorkout.id : "";
	const currentDate = workoutStart(currentWorkout).slice(0, 10);
	const currentExercises: any[] = Array.isArray(currentWorkout?.exercises)
		? currentWorkout.exercises
		: [];

	// Earlier workouts, most recent first, so the first match is the closest prior.
	const priors = [...priorWorkouts].sort((a, b) => {
		const da = workoutStart(a);
		const db = workoutStart(b);
		return da < db ? 1 : da > db ? -1 : 0;
	});

	let withoutPrevious = 0;
	const exercises: ExerciseProgression[] = currentExercises.map((exercise) => {
		const templateId =
			typeof exercise?.exercise_template_id === "string"
				? exercise.exercise_template_id
				: "";
		const current = computeExerciseOccurrence(exercise, currentId, currentDate);

		let previous: ExerciseOccurrence | null = null;
		for (const workout of priors) {
			const exs: any[] = Array.isArray(workout?.exercises)
				? workout.exercises
				: [];
			const match = exs.find(
				(e) => e?.exercise_template_id === templateId,
			);
			if (match) {
				previous = computeExerciseOccurrence(
					match,
					typeof workout?.id === "string" ? workout.id : "",
					workoutStart(workout).slice(0, 10),
				);
				break;
			}
		}
		if (previous === null) withoutPrevious++;

		const entry: ExerciseProgression = {
			exercise_template_id: templateId,
			current,
			previous,
			delta: previous ? computeProgressionDelta(current, previous) : null,
		};
		if (typeof exercise?.title === "string") {
			entry.exercise_title = exercise.title;
		}
		return entry;
	});

	return {
		session: currentId
			? {
					workout_id: currentId,
					date: currentDate,
					exercise_count: currentExercises.length,
				}
			: null,
		exercises,
		scanned_workouts: options.scannedWorkouts,
		exercises_without_previous: withoutPrevious,
		truncated: options.truncated,
	};
}

// ── Personal records ─────────────────────────────────────────────────────────
//
// Fact-only maxima per exercise_template_id across scanned workouts. A "record"
// is the maximum observed value — no judgment about whether it's meaningful.
// Warmup sets excluded.

export interface PersonalRecordEntry {
	/** The record value (kg for weight/1RM, count for reps). */
	value: number;
	weight_kg: number | null;
	reps: number | null;
	date: string;
	workout_id: string;
}

export interface ExercisePersonalRecords {
	exercise_template_id: string;
	exercise_title?: string;
	max_weight_kg: PersonalRecordEntry | null;
	best_estimated_1rm_kg: PersonalRecordEntry | null;
	max_reps: PersonalRecordEntry | null;
}

export interface PersonalRecordsResult {
	records: ExercisePersonalRecords[];
	scanned_workouts: number;
	truncated: boolean;
}

interface RecordAccumulator {
	title?: string;
	maxWeight: PersonalRecordEntry | null;
	best1rm: PersonalRecordEntry | null;
	maxReps: PersonalRecordEntry | null;
}

/**
 * Finds per-exercise maxima (heaviest set, best Epley 1RM, most reps) across the
 * given workouts, keyed by exercise_template_id. Warmup sets are excluded.
 *
 * @param options.templateId - Restrict to a single exercise template
 */
export function analyzePersonalRecords(
	workouts: any[],
	options: { scannedWorkouts: number; truncated: boolean; templateId?: string },
): PersonalRecordsResult {
	const groups = new Map<string, RecordAccumulator>();

	for (const workout of workouts) {
		const workoutId = typeof workout?.id === "string" ? workout.id : "";
		const date = workoutStart(workout).slice(0, 10);
		const exercises: any[] = Array.isArray(workout?.exercises)
			? workout.exercises
			: [];

		for (const exercise of exercises) {
			const templateId =
				typeof exercise?.exercise_template_id === "string"
					? exercise.exercise_template_id
					: "";
			if (options.templateId && templateId !== options.templateId) continue;

			const group =
				groups.get(templateId) ??
				({ maxWeight: null, best1rm: null, maxReps: null } as RecordAccumulator);
			if (typeof exercise?.title === "string") group.title = exercise.title;

			const sets: any[] = Array.isArray(exercise?.sets) ? exercise.sets : [];
			for (const set of sets.filter(isEffectiveSet)) {
				const weight = numeric(set?.weight_kg);
				const reps = numeric(set?.reps);
				const base = { weight_kg: weight, reps, date, workout_id: workoutId };

				if (weight !== null && (!group.maxWeight || weight > group.maxWeight.value)) {
					group.maxWeight = { value: weight, ...base };
				}
				const e1rm = estimatedOneRepMax(weight, reps);
				if (e1rm !== null && (!group.best1rm || e1rm > group.best1rm.value)) {
					group.best1rm = { value: roundTo2(e1rm), ...base };
				}
				if (reps !== null && (!group.maxReps || reps > group.maxReps.value)) {
					group.maxReps = { value: reps, ...base };
				}
			}

			groups.set(templateId, group);
		}
	}

	const records: ExercisePersonalRecords[] = [...groups.entries()].map(
		([templateId, group]) => {
			const entry: ExercisePersonalRecords = {
				exercise_template_id: templateId,
				max_weight_kg: group.maxWeight,
				best_estimated_1rm_kg: group.best1rm,
				max_reps: group.maxReps,
			};
			if (group.title !== undefined) entry.exercise_title = group.title;
			return entry;
		},
	);

	return {
		records,
		scanned_workouts: options.scannedWorkouts,
		truncated: options.truncated,
	};
}

export function formatPersonalRecords(result: PersonalRecordsResult): string {
	if (result.records.length === 0) return "No exercises found to compute records.";
	const lines: string[] = ["Personal records (maxima across scanned workouts):"];
	for (const rec of result.records) {
		const title = rec.exercise_title ?? rec.exercise_template_id;
		const parts: string[] = [];
		if (rec.max_weight_kg) parts.push(`max weight ${rec.max_weight_kg.value}kg (${rec.max_weight_kg.date})`);
		if (rec.best_estimated_1rm_kg) parts.push(`est 1RM ${rec.best_estimated_1rm_kg.value}kg`);
		if (rec.max_reps) parts.push(`max reps ${rec.max_reps.value}`);
		lines.push(`${title}: ${parts.join(", ") || "no effective sets"}`);
	}
	if (result.truncated) {
		lines.push(`(Note: only the first ${result.scanned_workouts} workouts were scanned; older records may exist.)`);
	}
	return lines.join("\n");
}

function formatTopSet(top: ProgressionTopSet | null): string {
	if (!top) return "n/a";
	return `${top.weight_kg}kg×${top.reps ?? "?"}`;
}

/** Neutral, factual rendering — no good/bad language. */
export function formatProgressionDeltas(result: ProgressionDeltasResult): string {
	if (!result.session || result.exercises.length === 0) {
		return "No exercises to compare in the current session.";
	}

	const lines: string[] = [];
	lines.push(
		`Progression deltas for session ${result.session.date} (${result.session.exercise_count} exercise(s)):`,
	);
	for (const ex of result.exercises) {
		const title = ex.exercise_title ?? ex.exercise_template_id;
		const c = ex.current;
		if (!ex.previous) {
			lines.push(
				`${title}: no previous occurrence found. Current top set ${formatTopSet(c.top_set)}, effective sets ${c.effective_sets}, volume ${c.total_volume_kg}kg.`,
			);
		} else {
			const p = ex.previous;
			lines.push(
				`${title}: top set ${formatTopSet(c.top_set)} vs ${formatTopSet(p.top_set)}; effective sets ${c.effective_sets} vs ${p.effective_sets}; volume ${c.total_volume_kg} vs ${p.total_volume_kg}kg (prev ${p.date}).`,
			);
		}
	}
	if (result.truncated) {
		lines.push(
			`(Note: only the first ${result.scanned_workouts} workouts were scanned; some previous occurrences may be older.)`,
		);
	}
	return lines.join("\n");
}

// ── Workout comparison ───────────────────────────────────────────────────────
//
// Raw diff between two specific workouts. Components are returned separately —
// never a single score (tonnage alone misleads) and never a "shorter/worse"
// label. Warmup excluded. The caller decides whether the two are comparable.

export interface WorkoutComparisonSide {
	workout_id: string;
	date: string;
	/** Sum of weight_kg × reps over effective sets. */
	tonnage_kg: number;
	effective_sets: number;
	duration_seconds: number | null;
	/** Distinct exercise_template_ids present in the workout. */
	exercise_template_ids: string[];
}

export interface ComparisonExerciseRef {
	exercise_template_id: string;
	exercise_title?: string;
}

export interface WorkoutComparisonResult {
	a: WorkoutComparisonSide;
	b: WorkoutComparisonSide;
	delta: {
		tonnage_kg: number;
		effective_sets: number;
		duration_seconds: number | null;
	};
	exercises: {
		in_both: ComparisonExerciseRef[];
		only_in_a: ComparisonExerciseRef[];
		only_in_b: ComparisonExerciseRef[];
	};
}

function workoutDurationSeconds(workout: any): number | null {
	const start = workoutStart(workout);
	const end = typeof workout?.end_time === "string" ? workout.end_time : "";
	if (!start || !end) return null;
	const startMs = Date.parse(start);
	const endMs = Date.parse(end);
	if (Number.isNaN(startMs) || Number.isNaN(endMs)) return null;
	return Math.round((endMs - startMs) / 1000);
}

function comparisonSide(workout: any): WorkoutComparisonSide {
	const exercises: any[] = Array.isArray(workout?.exercises)
		? workout.exercises
		: [];
	let tonnage = 0;
	let effectiveSets = 0;
	const templateIds: string[] = [];

	for (const exercise of exercises) {
		const templateId =
			typeof exercise?.exercise_template_id === "string"
				? exercise.exercise_template_id
				: "";
		if (templateId && !templateIds.includes(templateId)) {
			templateIds.push(templateId);
		}
		const sets: any[] = Array.isArray(exercise?.sets) ? exercise.sets : [];
		for (const set of sets.filter(isEffectiveSet)) {
			effectiveSets++;
			const weight = numeric(set?.weight_kg);
			const reps = numeric(set?.reps);
			if (weight !== null && reps !== null) tonnage += weight * reps;
		}
	}

	return {
		workout_id: typeof workout?.id === "string" ? workout.id : "",
		date: workoutStart(workout).slice(0, 10),
		tonnage_kg: roundTo2(tonnage),
		effective_sets: effectiveSets,
		duration_seconds: workoutDurationSeconds(workout),
		exercise_template_ids: templateIds,
	};
}

/** Raw component-wise diff of two workouts. No composite score, no labels. */
export function compareWorkouts(
	workoutA: any,
	workoutB: any,
): WorkoutComparisonResult {
	const a = comparisonSide(workoutA);
	const b = comparisonSide(workoutB);

	// Title lookup for the exercise presence lists.
	const titles = new Map<string, string>();
	for (const workout of [workoutA, workoutB]) {
		const exs: any[] = Array.isArray(workout?.exercises)
			? workout.exercises
			: [];
		for (const ex of exs) {
			if (
				typeof ex?.exercise_template_id === "string" &&
				typeof ex?.title === "string"
			) {
				titles.set(ex.exercise_template_id, ex.title);
			}
		}
	}
	const ref = (templateId: string): ComparisonExerciseRef => {
		const title = titles.get(templateId);
		return title !== undefined
			? { exercise_template_id: templateId, exercise_title: title }
			: { exercise_template_id: templateId };
	};

	const setB = new Set(b.exercise_template_ids);
	const setA = new Set(a.exercise_template_ids);

	return {
		a,
		b,
		delta: {
			tonnage_kg: roundTo2(a.tonnage_kg - b.tonnage_kg),
			effective_sets: a.effective_sets - b.effective_sets,
			duration_seconds:
				a.duration_seconds !== null && b.duration_seconds !== null
					? a.duration_seconds - b.duration_seconds
					: null,
		},
		exercises: {
			in_both: a.exercise_template_ids.filter((t) => setB.has(t)).map(ref),
			only_in_a: a.exercise_template_ids.filter((t) => !setB.has(t)).map(ref),
			only_in_b: b.exercise_template_ids.filter((t) => !setA.has(t)).map(ref),
		},
	};
}

// ── Routine instances ────────────────────────────────────────────────────────
//
// Finding the previous instance of the SAME routine_id is a fact the MCP can
// establish. Matching "same session" without a routine_id is fuzzy and
// user-specific — the client does that and passes explicit workout_ids.

export interface RoutineInstanceRef {
	workout_id: string;
	date: string;
}

export interface PreviousRoutineInstanceResult {
	routine_id: string;
	anchor: RoutineInstanceRef | null;
	previous: RoutineInstanceRef | null;
	total_instances: number;
	scanned_workouts: number;
	truncated: boolean;
}

/**
 * Finds the previous instance of a routine.
 *
 * @param options.beforeWorkoutId - Anchor instance; default is the most recent.
 */
export function findPreviousRoutineInstance(
	workouts: any[],
	routineId: string,
	options: { scannedWorkouts: number; truncated: boolean; beforeWorkoutId?: string },
): PreviousRoutineInstanceResult {
	const instances = workouts
		.filter((w) => w?.routine_id === routineId)
		.map((w) => ({
			workout_id: typeof w?.id === "string" ? w.id : "",
			start: workoutStart(w),
		}))
		.sort((a, b) => (a.start < b.start ? 1 : a.start > b.start ? -1 : 0));

	const toRef = (i: { workout_id: string; start: string }): RoutineInstanceRef => ({
		workout_id: i.workout_id,
		date: i.start.slice(0, 10),
	});

	let anchorIdx = 0;
	if (options.beforeWorkoutId) {
		anchorIdx = instances.findIndex(
			(i) => i.workout_id === options.beforeWorkoutId,
		);
	}

	const anchor = anchorIdx >= 0 ? (instances[anchorIdx] ?? null) : null;
	const previous =
		anchorIdx >= 0 ? (instances[anchorIdx + 1] ?? null) : null;

	return {
		routine_id: routineId,
		anchor: anchor ? toRef(anchor) : null,
		previous: previous ? toRef(previous) : null,
		total_instances: instances.length,
		scanned_workouts: options.scannedWorkouts,
		truncated: options.truncated,
	};
}

// ── Muscle balance ───────────────────────────────────────────────────────────
//
// Distribution of effective sets / volume per primary muscle group over a
// window. Numbers only — never a "balanced/unbalanced" verdict.

export interface MuscleGroupVolume {
	muscle_group: string;
	effective_sets: number;
	total_volume_kg: number;
	exercise_count: number;
}

export interface MuscleBalanceResult {
	since: string;
	workouts_counted: number;
	by_muscle_group: MuscleGroupVolume[];
	unmapped_exercises: number;
	truncated: boolean;
}

/**
 * Aggregates effective sets and volume per primary muscle group.
 *
 * @param muscleGroupByTemplate - template_id → primary_muscle_group (from the catalog)
 */
export function analyzeMuscleBalance(
	workouts: any[],
	muscleGroupByTemplate: Record<string, string>,
	since: string,
	options: { truncated: boolean },
): MuscleBalanceResult {
	const inWindow = workouts.filter(
		(w) => workoutStart(w).slice(0, 10) >= since,
	);

	const groups = new Map<string, MuscleGroupVolume>();
	let unmapped = 0;

	for (const workout of inWindow) {
		const exercises: any[] = Array.isArray(workout?.exercises)
			? workout.exercises
			: [];
		for (const exercise of exercises) {
			const templateId =
				typeof exercise?.exercise_template_id === "string"
					? exercise.exercise_template_id
					: "";
			const muscleGroup = muscleGroupByTemplate[templateId];
			if (!muscleGroup) {
				unmapped++;
				continue;
			}
			const group =
				groups.get(muscleGroup) ??
				({
					muscle_group: muscleGroup,
					effective_sets: 0,
					total_volume_kg: 0,
					exercise_count: 0,
				} as MuscleGroupVolume);
			group.exercise_count++;
			const sets: any[] = Array.isArray(exercise?.sets) ? exercise.sets : [];
			for (const set of sets.filter(isEffectiveSet)) {
				group.effective_sets++;
				const weight = numeric(set?.weight_kg);
				const reps = numeric(set?.reps);
				if (weight !== null && reps !== null) {
					group.total_volume_kg += weight * reps;
				}
			}
			groups.set(muscleGroup, group);
		}
	}

	const byGroup = [...groups.values()]
		.map((g) => ({ ...g, total_volume_kg: roundTo2(g.total_volume_kg) }))
		.sort((a, b) => b.effective_sets - a.effective_sets);

	return {
		since,
		workouts_counted: inWindow.length,
		by_muscle_group: byGroup,
		unmapped_exercises: unmapped,
		truncated: options.truncated,
	};
}
