import { describe, it, expect, beforeEach } from "vitest";
import { HevyClient } from "../../src/lib/client";
import { mockFetchSuccess } from "../setup";

describe("HevyClient - exercise template catalog cache", () => {
	let client: HevyClient;

	beforeEach(() => {
		(global.fetch as any).mockReset();
		client = new HevyClient({ apiKey: "test-api-key" });
	});

	function mockCatalogPages() {
		// Two pages of templates
		mockFetchSuccess({
			page: 1,
			page_count: 2,
			exercise_templates: [{ id: "A", title: "Bench" }],
		});
		mockFetchSuccess({
			page: 2,
			page_count: 2,
			exercise_templates: [{ id: "B", title: "Squat" }],
		});
	}

	it("aggregates all pages", async () => {
		mockCatalogPages();

		const all = await client.getAllExerciseTemplates();

		expect(all.map((t) => t.id)).toEqual(["A", "B"]);
		expect((global.fetch as any).mock.calls).toHaveLength(2);
	});

	it("caches the catalog (no refetch on the second call)", async () => {
		mockCatalogPages();

		await client.getAllExerciseTemplates();
		const second = await client.getAllExerciseTemplates();

		expect(second.map((t) => t.id)).toEqual(["A", "B"]);
		// Still only the two initial page fetches — served from cache
		expect((global.fetch as any).mock.calls).toHaveLength(2);
	});

	it("force refetches when asked", async () => {
		mockCatalogPages();
		await client.getAllExerciseTemplates();

		mockCatalogPages();
		await client.getAllExerciseTemplates({ force: true });

		expect((global.fetch as any).mock.calls).toHaveLength(4);
	});

	it("invalidates the cache after creating a custom exercise", async () => {
		mockCatalogPages();
		await client.getAllExerciseTemplates();

		// Creating an exercise clears the cache
		mockFetchSuccess({ id: "new" }, 200);
		await client.createExerciseTemplate({ exercise: {} });

		// Next call must refetch
		mockCatalogPages();
		await client.getAllExerciseTemplates();

		// 2 (initial) + 1 (create) + 2 (refetch) = 5
		expect((global.fetch as any).mock.calls).toHaveLength(5);
	});
});
