import { describe, it, expect } from "vitest";
import {
	analyzeBodyProgress,
	formatBodyProgress,
	analyzeTrainingSummary,
	formatTrainingSummary,
	analyzeProgressionDeltas,
	computeExerciseOccurrence,
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

	it("renders per-metric trend lines with direction arrows", () => {
		const summary = analyzeBodyProgress(
			[
				{ date: "2024-08-01", weight_kg: 82 },
				{ date: "2024-09-01", weight_kg: 80 },
			],
			"2024-01-01",
		);
		const text = formatBodyProgress(summary, 8);
		expect(text).toContain("weight_kg: 82 → 80");
		expect(text).toContain("▼ -2");
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

	it("counts workouts, sets, exercises and volume in the window", () => {
		const s = analyzeTrainingSummary(workouts, "2024-07-15", 4);
		expect(s.workoutCount).toBe(2);
		expect(s.activeDays).toBe(2);
		expect(s.totalExercises).toBe(3);
		expect(s.totalSets).toBe(5);
		expect(s.totalVolumeKg).toBe(2100); // 500+500+500+600
		expect(s.firstDate).toBe("2024-08-01");
		expect(s.lastDate).toBe("2024-08-03");
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
		expect(s.totalSets).toBe(2);
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
});
