import { describe, it, expect, beforeEach } from "vitest";
import { HevyClient, HevyApiError } from "../../src/lib/client";
import { mockFetchSuccess, mockFetchError } from "../setup";

/**
 * Retry/backoff behavior. retryDelayMs: 0 keeps the tests instant.
 */
describe("HevyClient - retry & backoff", () => {
	const TEST_API_KEY = "test-api-key";

	function client(maxRetries: number) {
		return new HevyClient({
			apiKey: TEST_API_KEY,
			maxRetries,
			retryDelayMs: 0,
		});
	}

	beforeEach(() => {
		(global.fetch as any).mockReset();
	});

	it("does not retry by default (maxRetries defaults to 0)", async () => {
		const c = new HevyClient({ apiKey: TEST_API_KEY });
		mockFetchError(500, "Server Error");

		await expect(c.getWorkouts()).rejects.toBeInstanceOf(HevyApiError);
		expect((global.fetch as any).mock.calls).toHaveLength(1);
	});

	it("retries a GET on 500 and succeeds", async () => {
		mockFetchError(500, "Server Error");
		mockFetchSuccess({ page: 1, page_count: 1, workouts: [] });

		const result = await client(2).getWorkouts();

		expect(result.workouts).toEqual([]);
		expect((global.fetch as any).mock.calls).toHaveLength(2);
	});

	it("retries a GET on 429 and succeeds", async () => {
		mockFetchError(429, "Too Many Requests");
		mockFetchSuccess({ workout_count: 7 });

		const result = await client(2).getWorkoutsCount();

		expect(result.workout_count).toBe(7);
		expect((global.fetch as any).mock.calls).toHaveLength(2);
	});

	it("gives up after maxRetries and throws the last error", async () => {
		mockFetchError(503, "Unavailable");
		mockFetchError(503, "Unavailable");
		mockFetchError(503, "Unavailable");

		await expect(client(2).getWorkouts()).rejects.toMatchObject({
			status: 503,
		});
		// initial attempt + 2 retries
		expect((global.fetch as any).mock.calls).toHaveLength(3);
	});

	it("retries writes only on 429, not on 5xx", async () => {
		// 5xx on a POST must NOT be retried (avoid duplicate creates)
		mockFetchError(500, "Server Error");

		await expect(
			client(3).createWorkout({ workout: {} }),
		).rejects.toMatchObject({ status: 500 });
		expect((global.fetch as any).mock.calls).toHaveLength(1);
	});

	it("retries a write on 429", async () => {
		mockFetchError(429, "Too Many Requests");
		mockFetchSuccess({ id: "w1" }, 201);

		const result = await client(2).createWorkout({ workout: {} });

		expect(result.id).toBe("w1");
		expect((global.fetch as any).mock.calls).toHaveLength(2);
	});

	it("does not retry a 4xx client error (e.g. 404)", async () => {
		mockFetchError(404, "Not Found");

		await expect(client(3).getWorkout("x")).rejects.toMatchObject({
			status: 404,
		});
		expect((global.fetch as any).mock.calls).toHaveLength(1);
	});
});
