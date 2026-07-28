import { describe, it, expect } from "vitest";
import {
	analyzeBodyProgress,
	formatBodyProgress,
	analyzeTrainingSummary,
	formatTrainingSummary,
	analyzeProgressionDeltas,
	computeExerciseOccurrence,
	analyzePersonalRecords,
	compareWorkouts,
	findPreviousRoutineInstance,
	analyzeMuscleBalance,
} from "../../src/lib/analysis.js";

describe("analysis - analyzeBodyProgress", () => {
	const measurements = [
		{ date: "2024-08-01", weight_kg: 82, waist: 84 },
		{ date: "2024-08-15", weight_kg: 81, waist: 83 },
		{ date: "2024-09-01", weight_kg: 80, waist: 82, fat_percent: 18 },
		// Outside the window when since = 2024-08-10:
		{ date: "2024-07-01", weight_kg: 85 },
	];

	it("filters to entries on/after `since`", () => {
		const summary = analyzeBodyProgress(measurements, "2024-08-10");
		expect(summary.entryCount).toBe(2); // 08-15 and 09-01
		expect(summary.firstDate).toBe("2024-08-15");
		expect(summary.lastDate).toBe("2024-09-01");
	});

	it("computes first/last/change per metric across the window", () => {
		const summary = analyzeBodyProgress(measurements, "2024-01-01");
		const weight = summary.metrics.find((m) => m.field === "weight_kg");
		expect(weight).toMatchObject({
			first: 85, // earliest = 2024-07-01
			last: 80, // latest = 2024-09-01
			change: -5,
			count: 4,
			firstDate: "2024-07-01",
			lastDate: "2024-09-01",
		});
	});

	it("uses only entries that recorded a given metric for first/last", () => {
		const summary = analyzeBodyProgress(measurements, "2024-01-01");
		const fat = summary.metrics.find((m) => m.field === "fat_percent");
		// Only one entry has fat_percent
		expect(fat).toMatchObject({
			first: 18,
			last: 18,
			change: 0,
			count: 1,
		});
	});

	it("omits metrics with no data in the window", () => {
		const summary = analyzeBodyProgress(measurements, "2024-01-01");
		// No entry records e.g. neck_cm
		expect(summary.metrics.find((m) => m.field === "neck_cm")).toBeUndefined();
	});

	it("rounds change to 2 decimals", () => {
		const summary = analyzeBodyProgress(
			[
				{ date: "2024-08-01", weight_kg: 80.15 },
				{ date: "2024-08-08", weight_kg: 80.0 },
			],
			"2024-01-01",
		);
		expect(summary.metrics[0].change).toBe(-0.15);
	});

	it("returns an empty summary when no entries are in the window", () => {
		const summary = analyzeBodyProgress(measurements, "2030-01-01");
		expect(summary.entryCount).toBe(0);
		expect(summary.metrics).toEqual([]);
		expect(summary.firstDate).toBeUndefined();
	});

	it("ignores entries without a valid date", () => {
		const summary = analyzeBodyProgress(
			[{ weight_kg: 80 } as never, { date: "2024-08-01", weight_kg: 79 }],
			"2024-01-01",
		);
		expect(summary.entryCount).toBe(1);
	});
});

describe("analysis - formatBodyProgress", () => {
	it("reports a friendly message when there is no data", () => {
		const summary = analyzeBodyProgress([], "2024-08-01");
		expect(formatBodyProgress(summary, 8)).toContain(
			"No body measurements logged in the last 8 week(s)",
		);
	});

	it("renders per-metric trend lines with signed change, no judgment arrows", () => {
		const summary = analyzeBodyProgress(
			[
				{ date: "2024-08-01", weight_kg: 82 },
				{ date: "2024-09-01", weight_kg: 80 },
			],
			"2024-01-01",
		);
		const text = formatBodyProgress(summary, 8);
		expect(text).toContain("weight_kg: 82 → 80");
		expect(text).toContain("change -2");
		expect(text).not.toContain("▼");
		expect(text).not.toContain("▲");
	});
});

describe("analysis - analyzeTrainingSummary", () => {
	const workouts = [
		{
			start_time: "2024-08-01T10:00:00Z",
			exercises: [
				{
					sets: [
						{ weight_kg: 100, reps: 5 }, // 500
						{ weight_kg: 100, reps: 5 }, // 500
					],
				},
				{ sets: [{ weight_kg: 50, reps: 10 }] }, // 500
			],
		},
		{
			start_time: "2024-08-03T10:00:00Z",
			exercises: [{ sets: [{ weight_kg: 60, reps: 10 }, { reps: 12 }] }], // 600, second set no weight
		},
		// Outside the window (since = 2024-07-15):
		{ start_time: "2024-06-01T10:00:00Z", exercises: [{ sets: [{ weight_kg: 80, reps: 5 }] }] },
	];

	it("counts workouts, effective sets, exercises and volume in the window", () => {
		const s = analyzeTrainingSummary(workouts, "2024-07-15", 4);
		expect(s.workoutCount).toBe(2);
		expect(s.activeDays).toBe(2);
		expect(s.totalExercises).toBe(3);
		expect(s.effectiveSets).toBe(5);
		expect(s.totalVolumeKg).toBe(2100); // 500+500+500+600
		expect(s.firstDate).toBe("2024-08-01");
		expect(s.lastDate).toBe("2024-08-03");
	});

	it("excludes warmup sets from effectiveSets and volume", () => {
		const s = analyzeTrainingSummary(
			[
				{
					start_time: "2024-08-01T10:00:00Z",
					exercises: [
						{
							sets: [
								{ type: "warmup", weight_kg: 60, reps: 10 }, // excluded
								{ type: "normal", weight_kg: 100, reps: 5 }, // 500
							],
						},
					],
				},
			],
			"2024-01-01",
			1,
		);
		expect(s.effectiveSets).toBe(1);
		expect(s.totalVolumeKg).toBe(500);
	});

	it("computes average workouts per week from the window length", () => {
		const s = analyzeTrainingSummary(workouts, "2024-07-15", 4);
		expect(s.avgWorkoutsPerWeek).toBe(0.5); // 2 / 4
	});

	it("only counts a set toward volume when weight and reps are both numeric", () => {
		const s = analyzeTrainingSummary(
			[{ start_time: "2024-08-01T10:00:00Z", exercises: [{ sets: [{ reps: 10 }, { weight_kg: 40 }] }] }],
			"2024-01-01",
			1,
		);
		expect(s.effectiveSets).toBe(2);
		expect(s.totalVolumeKg).toBe(0);
	});

	it("returns an empty summary when no workouts are in the window", () => {
		const s = analyzeTrainingSummary(workouts, "2030-01-01", 4);
		expect(s.workoutCount).toBe(0);
		expect(s.totalVolumeKg).toBe(0);
		expect(s.firstDate).toBeUndefined();
	});

	it("formats a friendly report", () => {
		const s = analyzeTrainingSummary(workouts, "2024-07-15", 4);
		const text = formatTrainingSummary(s, 4);
		expect(text).toContain("Workouts: 2");
		expect(text).toContain("Volume: 2100 kg");
	});

	it("formats a no-data message", () => {
		const s = analyzeTrainingSummary([], "2024-07-15", 4);
		expect(formatTrainingSummary(s, 4)).toContain("No workouts logged");
	});
});

describe("analysis - computeExerciseOccurrence", () => {
	it("excludes warmup sets from every aggregation", () => {
		const occ = computeExerciseOccurrence(
			{
				sets: [
					{ type: "warmup", weight_kg: 60, reps: 10 }, // excluded
					{ type: "normal", weight_kg: 100, reps: 5 }, // 500
					{ type: "normal", weight_kg: 100, reps: 5 }, // 500
				],
			},
			"w1",
			"2024-08-01",
		);
		expect(occ.effective_sets).toBe(2);
		expect(occ.total_volume_kg).toBe(1000);
		expect(occ.total_reps).toBe(10);
		expect(occ.max_weight_kg).toBe(100);
	});

	it("picks the heaviest effective set as top_set and computes Epley 1RM", () => {
		const occ = computeExerciseOccurrence(
			{
				sets: [
					{ type: "normal", weight_kg: 90, reps: 8 },
					{ type: "normal", weight_kg: 100, reps: 5, rpe: 8 },
				],
			},
			"w1",
			"2024-08-01",
		);
		expect(occ.top_set).toEqual({ weight_kg: 100, reps: 5, rpe: 8 });
		// Epley best = max(90*(1+8/30)=114, 100*(1+5/30)=116.67) = 116.67
		expect(occ.best_estimated_1rm_kg).toBe(116.67);
	});

	it("handles bodyweight/duration sets (no weight) gracefully", () => {
		const occ = computeExerciseOccurrence(
			{ sets: [{ type: "normal", reps: 12 }, { type: "normal", reps: 10 }] },
			"w1",
			"2024-08-01",
		);
		expect(occ.effective_sets).toBe(2);
		expect(occ.total_reps).toBe(22);
		expect(occ.total_volume_kg).toBe(0);
		expect(occ.max_weight_kg).toBeNull();
		expect(occ.best_estimated_1rm_kg).toBeNull();
		expect(occ.top_set).toBeNull();
	});
});

describe("analysis - analyzeProgressionDeltas", () => {
	const bench = "TPL_BENCH";
	const squat = "TPL_SQUAT";

	const current = {
		id: "w_today",
		start_time: "2024-08-10T10:00:00Z",
		exercises: [
			{
				exercise_template_id: bench,
				title: "Bench Press",
				sets: [
					{ type: "warmup", weight_kg: 60, reps: 10 },
					{ type: "normal", weight_kg: 102.5, reps: 5 },
				],
			},
		],
	};

	// Most recent bench occurrence is 08-05; there's a squat-only day in between.
	const priors = [
		{
			id: "w_squat",
			start_time: "2024-08-08T10:00:00Z",
			exercises: [
				{ exercise_template_id: squat, sets: [{ type: "normal", weight_kg: 140, reps: 5 }] },
			],
		},
		{
			id: "w_bench_prev",
			start_time: "2024-08-05T10:00:00Z",
			exercises: [
				{
					exercise_template_id: bench,
					sets: [
						{ type: "warmup", weight_kg: 60, reps: 10 },
						{ type: "normal", weight_kg: 100, reps: 5 },
					],
				},
			],
		},
		{
			id: "w_bench_older",
			start_time: "2024-07-20T10:00:00Z",
			exercises: [
				{ exercise_template_id: bench, sets: [{ type: "normal", weight_kg: 95, reps: 5 }] },
			],
		},
	];

	it("matches the previous occurrence by template_id, skipping intermediate workouts", () => {
		const r = analyzeProgressionDeltas(current, priors, {
			scannedWorkouts: 4,
			truncated: false,
		});
		expect(r.session?.workout_id).toBe("w_today");
		const benchEntry = r.exercises[0];
		// Closest prior bench day is 08-05, NOT the squat day in between
		expect(benchEntry.previous?.workout_id).toBe("w_bench_prev");
		expect(benchEntry.previous?.date).toBe("2024-08-05");
	});

	it("returns raw deltas (current − previous), no labels", () => {
		const r = analyzeProgressionDeltas(current, priors, {
			scannedWorkouts: 4,
			truncated: false,
		});
		const d = r.exercises[0].delta;
		expect(d?.top_set_weight_kg).toBe(2.5); // 102.5 − 100
		expect(d?.max_weight_kg).toBe(2.5);
		expect(d?.effective_sets).toBe(0);
	});

	it("marks first-ever occurrences with previous null and counts them", () => {
		const r = analyzeProgressionDeltas(
			{
				id: "w1",
				start_time: "2024-08-10T10:00:00Z",
				exercises: [
					{ exercise_template_id: "NEW", sets: [{ type: "normal", weight_kg: 50, reps: 8 }] },
				],
			},
			priors,
			{ scannedWorkouts: 4, truncated: false },
		);
		expect(r.exercises[0].previous).toBeNull();
		expect(r.exercises[0].delta).toBeNull();
		expect(r.exercises_without_previous).toBe(1);
	});

	it("passes through scan metadata and handles an empty session", () => {
		const r = analyzeProgressionDeltas(
			{ id: "w1", start_time: "2024-08-10T10:00:00Z", exercises: [] },
			[],
			{ scannedWorkouts: 7, truncated: true },
		);
		expect(r.exercises).toEqual([]);
		expect(r.scanned_workouts).toBe(7);
		expect(r.truncated).toBe(true);
	});

	it("includes top_set_rpe delta (fatigue signal) and null when RPE missing", () => {
		const withRpe = analyzeProgressionDeltas(
			{ id: "w", start_time: "2024-08-10T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5, rpe: 9 }] }] },
			[{ id: "p", start_time: "2024-08-03T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5, rpe: 7.5 }] }] }],
			{ scannedWorkouts: 2, truncated: false },
		);
		// Same load × reps, RPE up 1.5 — hidden fatigue, as a raw number
		expect(withRpe.exercises[0].delta?.top_set_rpe).toBe(1.5);
		expect(withRpe.exercises[0].previous?.top_set?.rpe).toBe(7.5);

		const noRpe = analyzeProgressionDeltas(
			{ id: "w", start_time: "2024-08-10T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }] },
			[{ id: "p", start_time: "2024-08-03T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }] }],
			{ scannedWorkouts: 2, truncated: false },
		);
		expect(noRpe.exercises[0].delta?.top_set_rpe).toBeNull();
	});

	it("returns an occurrences array (current + priors) when history_depth > 1", () => {
		const current = { id: "w0", start_time: "2024-08-10T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }] };
		const priors = [
			{ id: "w1", start_time: "2024-08-05T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 97.5, reps: 5 }] }] },
			{ id: "w2", start_time: "2024-07-28T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 95, reps: 5 }] }] },
			{ id: "w3", start_time: "2024-07-20T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 92.5, reps: 5 }] }] },
		];
		const r = analyzeProgressionDeltas(current, priors, { scannedWorkouts: 4, truncated: false, historyDepth: 2 });
		expect(r.exercises[0].occurrences?.map((o) => o.workout_id)).toEqual(["w0", "w1", "w2"]);
	});

	it("omits occurrences at the default history_depth of 1", () => {
		const r = analyzeProgressionDeltas(
			{ id: "w0", start_time: "2024-08-10T10:00:00Z", exercises: [{ exercise_template_id: "B", sets: [{ type: "normal", weight_kg: 100, reps: 5 }] }] },
			[],
			{ scannedWorkouts: 1, truncated: false },
		);
		expect(r.exercises[0].occurrences).toBeUndefined();
	});
});

describe("analysis - analyzePersonalRecords", () => {
	const workouts = [
		{
			id: "w1",
			start_time: "2024-08-01T10:00:00Z",
			exercises: [
				{
					exercise_template_id: "BENCH",
					title: "Bench",
					sets: [
						{ type: "warmup", weight_kg: 200, reps: 1 }, // excluded even though "heavy"
						{ type: "normal", weight_kg: 100, reps: 5 },
					],
				},
			],
		},
		{
			id: "w2",
			start_time: "2024-08-05T10:00:00Z",
			exercises: [
				{
					exercise_template_id: "BENCH",
					sets: [{ type: "normal", weight_kg: 105, reps: 3 }],
				},
			],
		},
	];

	it("finds per-exercise maxima, excluding warmup", () => {
		const r = analyzePersonalRecords(workouts, {
			scannedWorkouts: 2,
			truncated: false,
		});
		const bench = r.records[0];
		expect(bench.max_weight_kg?.value).toBe(105);
		expect(bench.max_weight_kg?.workout_id).toBe("w2");
		expect(bench.max_reps?.value).toBe(5); // from the 100×5 set
		// best 1RM = max(100*(1+5/30)=116.67, 105*(1+3/30)=115.5) = 116.67
		expect(bench.best_estimated_1rm_kg?.value).toBe(116.67);
	});

	it("can restrict to a single template", () => {
		const r = analyzePersonalRecords(
			[
				...workouts,
				{
					id: "w3",
					start_time: "2024-08-06T10:00:00Z",
					exercises: [{ exercise_template_id: "SQUAT", sets: [{ type: "normal", weight_kg: 150, reps: 5 }] }],
				},
			],
			{ scannedWorkouts: 3, truncated: false, templateId: "BENCH" },
		);
		expect(r.records).toHaveLength(1);
		expect(r.records[0].exercise_template_id).toBe("BENCH");
	});
});

describe("analysis - compareWorkouts", () => {
	const a = {
		id: "A",
		start_time: "2024-08-10T10:00:00Z",
		end_time: "2024-08-10T11:00:00Z", // 3600s
		exercises: [
			{ exercise_template_id: "BENCH", title: "Bench", sets: [{ type: "warmup", weight_kg: 60, reps: 10 }, { type: "normal", weight_kg: 100, reps: 5 }] },
			{ exercise_template_id: "ROW", sets: [{ type: "normal", weight_kg: 80, reps: 10 }] },
		],
	};
	const b = {
		id: "B",
		start_time: "2024-08-03T10:00:00Z",
		end_time: "2024-08-03T10:45:00Z", // 2700s
		exercises: [
			{ exercise_template_id: "BENCH", sets: [{ type: "normal", weight_kg: 95, reps: 5 }] },
			{ exercise_template_id: "SQUAT", sets: [{ type: "normal", weight_kg: 140, reps: 5 }] },
		],
	};

	it("returns raw components and exercise presence, warmup excluded", () => {
		const r = compareWorkouts(a, b);
		expect(r.a.tonnage_kg).toBe(1300); // 100*5 + 80*10 (warmup 60*10 excluded)
		expect(r.b.tonnage_kg).toBe(1175); // 95*5 + 140*5
		expect(r.delta.tonnage_kg).toBe(125);
		expect(r.a.duration_seconds).toBe(3600);
		expect(r.delta.duration_seconds).toBe(900);
		expect(r.exercises.in_both.map((e) => e.exercise_template_id)).toEqual(["BENCH"]);
		expect(r.exercises.only_in_a.map((e) => e.exercise_template_id)).toEqual(["ROW"]);
		expect(r.exercises.only_in_b.map((e) => e.exercise_template_id)).toEqual(["SQUAT"]);
	});

	it("returns null duration deltas when a timestamp is missing", () => {
		const r = compareWorkouts({ id: "A", start_time: "2024-08-10T10:00:00Z", exercises: [] }, b);
		expect(r.a.duration_seconds).toBeNull();
		expect(r.delta.duration_seconds).toBeNull();
	});
});

describe("analysis - findPreviousRoutineInstance", () => {
	const workouts = [
		{ id: "w_new", routine_id: "R1", start_time: "2024-08-10T10:00:00Z" },
		{ id: "w_other", routine_id: "R2", start_time: "2024-08-08T10:00:00Z" },
		{ id: "w_prev", routine_id: "R1", start_time: "2024-08-03T10:00:00Z" },
		{ id: "w_old", routine_id: "R1", start_time: "2024-07-27T10:00:00Z" },
	];

	it("returns the most recent instance as anchor and the one before as previous", () => {
		const r = findPreviousRoutineInstance(workouts, "R1", {
			scannedWorkouts: 4,
			truncated: false,
		});
		expect(r.total_instances).toBe(3);
		expect(r.anchor?.workout_id).toBe("w_new");
		expect(r.previous?.workout_id).toBe("w_prev");
	});

	it("anchors on before_workout_id when given", () => {
		const r = findPreviousRoutineInstance(workouts, "R1", {
			scannedWorkouts: 4,
			truncated: false,
			beforeWorkoutId: "w_prev",
		});
		expect(r.anchor?.workout_id).toBe("w_prev");
		expect(r.previous?.workout_id).toBe("w_old");
	});

	it("returns nulls when the routine has no instances", () => {
		const r = findPreviousRoutineInstance(workouts, "NOPE", {
			scannedWorkouts: 4,
			truncated: false,
		});
		expect(r.total_instances).toBe(0);
		expect(r.anchor).toBeNull();
		expect(r.previous).toBeNull();
	});
});

describe("analysis - analyzeMuscleBalance", () => {
	const map = { BENCH: "chest", ROW: "upper_back", CURL: "biceps" };
	const workouts = [
		{
			start_time: "2024-08-10T10:00:00Z",
			exercises: [
				{ exercise_template_id: "BENCH", sets: [{ type: "warmup", weight_kg: 60, reps: 10 }, { type: "normal", weight_kg: 100, reps: 5 }, { type: "normal", weight_kg: 100, reps: 5 }] },
				{ exercise_template_id: "CUSTOM_UNMAPPED", sets: [{ type: "normal", weight_kg: 20, reps: 12 }] },
			],
		},
		{
			start_time: "2024-08-08T10:00:00Z",
			exercises: [{ exercise_template_id: "ROW", sets: [{ type: "normal", weight_kg: 80, reps: 10 }] }],
		},
		// Outside the window:
		{ start_time: "2024-06-01T10:00:00Z", exercises: [{ exercise_template_id: "CURL", sets: [{ type: "normal", weight_kg: 20, reps: 12 }] }] },
	];

	it("aggregates effective sets and volume per muscle group, excluding warmup", () => {
		const r = analyzeMuscleBalance(workouts, map, "2024-08-01", { truncated: false });
		const chest = r.by_muscle_group.find((g) => g.muscle_group === "chest");
		expect(chest?.effective_sets).toBe(2); // warmup excluded
		expect(chest?.total_volume_kg).toBe(1000);
		expect(r.workouts_counted).toBe(2); // June workout outside window
	});

	it("counts unmapped exercises and excludes out-of-window data", () => {
		const r = analyzeMuscleBalance(workouts, map, "2024-08-01", { truncated: false });
		expect(r.unmapped_exercises).toBe(1);
		// CURL (biceps) is in June, outside the window → not present
		expect(r.by_muscle_group.find((g) => g.muscle_group === "biceps")).toBeUndefined();
	});

	it("returns the distinct unmapped template_ids, not just the count", () => {
		const r = analyzeMuscleBalance(
			[
				{
					start_time: "2024-08-10T10:00:00Z",
					exercises: [
						{ exercise_template_id: "UNK1", sets: [{ type: "normal", reps: 10 }] },
						{ exercise_template_id: "UNK1", sets: [{ type: "normal", reps: 8 }] },
						{ exercise_template_id: "UNK2", sets: [{ type: "normal", reps: 8 }] },
					],
				},
			],
			{},
			"2024-01-01",
			{ truncated: false },
		);
		expect(r.unmapped_exercises).toBe(3); // occurrences
		expect([...r.unmapped_exercise_template_ids].sort()).toEqual(["UNK1", "UNK2"]); // distinct
	});

	it("returns a separate secondary block when requested, never merged into primary", () => {
		const r = analyzeMuscleBalance(
			[
				{
					start_time: "2024-08-10T10:00:00Z",
					exercises: [
						{ exercise_template_id: "BENCH", sets: [{ type: "warmup", weight_kg: 60, reps: 10 }, { type: "normal", weight_kg: 100, reps: 5 }, { type: "normal", weight_kg: 100, reps: 5 }] },
					],
				},
			],
			{ BENCH: "chest" },
			"2024-01-01",
			{ truncated: false, secondaryByTemplate: { BENCH: ["triceps", "shoulders"] } },
		);
		// Primary: chest gets the 2 effective sets (warmup excluded)
		expect(r.by_muscle_group.find((g) => g.muscle_group === "chest")?.effective_sets).toBe(2);
		// Secondary block attributes the same 2 sets to triceps AND shoulders
		expect(r.by_muscle_group_secondary?.find((g) => g.muscle_group === "triceps")?.effective_sets).toBe(2);
		expect(r.by_muscle_group_secondary?.find((g) => g.muscle_group === "shoulders")?.total_volume_kg).toBe(1000);
		// Never merged: triceps is NOT in the primary block
		expect(r.by_muscle_group.find((g) => g.muscle_group === "triceps")).toBeUndefined();
	});

	it("omits the secondary block by default", () => {
		const r = analyzeMuscleBalance([], {}, "2024-01-01", { truncated: false });
		expect(r.by_muscle_group_secondary).toBeUndefined();
		expect(r.unmapped_exercise_template_ids).toEqual([]);
	});
});
