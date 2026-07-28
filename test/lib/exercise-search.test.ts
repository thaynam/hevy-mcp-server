import { describe, it, expect } from "vitest";
import { filterExerciseTemplates } from "../../src/lib/exercise-search.js";

const catalog = [
	{ id: "A1", title: "Bench Press (Barbell)", type: "weight_reps", primary_muscle_group: "chest", is_custom: false },
	{ id: "A2", title: "Incline Bench Press (Dumbbell)", type: "weight_reps", primary_muscle_group: "chest" },
	{ id: "A3", title: "Squat (Barbell)", type: "weight_reps", primary_muscle_group: "quadriceps" },
	{ id: "A4", title: "My Custom Bench", type: "weight_reps", primary_muscle_group: "chest", is_custom: true },
];

describe("exercise-search - filterExerciseTemplates", () => {
	it("matches case-insensitively on the title", () => {
		const matches = filterExerciseTemplates(catalog, "bench", 20);
		expect(matches.map((m) => m.id)).toEqual(["A1", "A2", "A4"]);
	});

	it("returns a trimmed shape with is_custom coerced to boolean", () => {
		const [first, second] = filterExerciseTemplates(catalog, "bench press", 20);
		expect(first).toEqual({
			id: "A1",
			title: "Bench Press (Barbell)",
			type: "weight_reps",
			primary_muscle_group: "chest",
			is_custom: false,
		});
		// A2 has no is_custom field → coerced to false
		expect(second.is_custom).toBe(false);
	});

	it("respects the limit", () => {
		expect(filterExerciseTemplates(catalog, "bench", 2)).toHaveLength(2);
	});

	it("returns nothing for an empty query", () => {
		expect(filterExerciseTemplates(catalog, "   ", 20)).toEqual([]);
	});

	it("returns nothing when there is no match", () => {
		expect(filterExerciseTemplates(catalog, "deadlift", 20)).toEqual([]);
	});
});
