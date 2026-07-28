import { describe, it, expect } from "vitest";
import {
	analyzeBodyProgress,
	formatBodyProgress,
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
