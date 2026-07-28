/**
 * Configuration options for the Hevy API client
 */
export interface HevyClientConfig {
  /**
   * API key for authenticating with the Hevy API
   */
  apiKey: string;

  /**
   * Base URL for the Hevy API (defaults to the production API)
   */
  baseUrl?: string;

  /**
   * Maximum number of automatic retries for transient failures.
   * Defaults to 0 (no retries) to keep behavior explicit and predictable.
   * GET requests retry on network errors, 429, and 5xx; write requests retry
   * only on 429 (which means the request was rejected, not processed).
   */
  maxRetries?: number;

  /**
   * Base delay (ms) for exponential backoff between retries. Defaults to 300.
   * Actual delay is `retryDelayMs * 2^attempt`, capped, and overridden by a
   * `Retry-After` response header when present.
   */
  retryDelayMs?: number;
}

/**
 * Error class for Hevy API errors
 */
export class HevyApiError extends Error {
  status: number;
  data?: any;
  isRetryable: boolean;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = 'HevyApiError';
    this.status = status;
    this.data = data;
    this.isRetryable = status === 0 || status >= 500;
  }
}

/**
 * Client for interacting with the Hevy API
 */
export class HevyClient {
  private apiKey: string;
  private baseUrl: string;
  private maxRetries: number;
  private retryDelayMs: number;
  private readonly maxDelayMs = 8000;

  /**
   * Create a new Hevy API client
   */
  constructor(config: HevyClientConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.hevyapp.com';
    this.maxRetries = config.maxRetries ?? 0;
    this.retryDelayMs = config.retryDelayMs ?? 300;
  }

  /**
   * Whether a failed response is worth retrying for the given method.
   * - 429 (rate limited): safe to retry any method — the request was rejected.
   * - 5xx: retry reads only; retrying writes risks duplicate side effects.
   */
  private isRetryableStatus(method: string, status: number): boolean {
    if (status === 429) return true;
    if (method === 'GET' && status >= 500) return true;
    return false;
  }

  /**
   * Computes the backoff delay (ms) before a retry. Honors a numeric
   * `Retry-After` (seconds) header when present, otherwise exponential.
   */
  private backoffDelay(attempt: number, retryAfter?: string | null): number {
    if (retryAfter) {
      const seconds = Number(retryAfter);
      if (Number.isFinite(seconds) && seconds >= 0) {
        return Math.min(seconds * 1000, this.maxDelayMs);
      }
    }
    return Math.min(this.retryDelayMs * 2 ** attempt, this.maxDelayMs);
  }

  private sleep(ms: number): Promise<void> {
    if (ms <= 0) return Promise.resolve();
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Execute a request to the Hevy API
   */
  private async request<T>(
    path: string,
    options: {
      method: 'GET' | 'POST' | 'PUT' | 'DELETE';
      body?: unknown;
      queryParams?: Record<string, string | number | boolean | undefined>;
    }
  ): Promise<T> {
    const { method, body, queryParams } = options;

    // Construct query string if query parameters are provided
    const queryString = queryParams
      ? '?' + new URLSearchParams(
          Object.entries(queryParams)
            .filter(([_, value]) => value !== undefined)
            .map(([key, value]) => [key, String(value)])
        ).toString()
      : '';

    // Construct the full URL
    const url = `${this.baseUrl}${path}${queryString}`;

    // Set up request headers
    const headers = new Headers({
      'api-key': this.apiKey,
      'Content-Type': 'application/json',
    });

    const requestInit: RequestInit = {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
    };

    // Attempt the request, retrying transient failures with backoff.
    for (let attempt = 0; ; attempt++) {
      let response: Response;
      try {
        response = await fetch(url, requestInit);
      } catch (networkError) {
        // Network-level failure: retry reads only (writes are ambiguous).
        if (attempt < this.maxRetries && method === 'GET') {
          await this.sleep(this.backoffDelay(attempt));
          continue;
        }
        throw networkError;
      }

      // Parse the response
      const data = response.headers.get('Content-Type')?.includes('application/json')
        ? await response.json()
        : await response.text();

      // Handle error responses
      if (!response.ok) {
        if (
          attempt < this.maxRetries &&
          this.isRetryableStatus(method, response.status)
        ) {
          await this.sleep(
            this.backoffDelay(attempt, response.headers.get('Retry-After'))
          );
          continue;
        }

        throw new HevyApiError(
          `Hevy API request failed: ${response.status} ${response.statusText}`,
          response.status,
          data
        );
      }

      return data as T;
    }
  }

  /**
   * Helper method for GET requests
   */
  private async get<T>(
    path: string,
    queryParams?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>(path, { method: 'GET', ...(queryParams !== undefined ? { queryParams } : {}) });
  }

  /**
   * Helper method for POST requests
   */
  private async post<T>(
    path: string,
    body?: unknown,
    queryParams?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>(path, { method: 'POST', ...(body !== undefined ? { body } : {}), ...(queryParams !== undefined ? { queryParams } : {}) });
  }

  /**
   * Helper method for PUT requests
   */
  private async put<T>(
    path: string,
    body?: unknown,
    queryParams?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>(path, { method: 'PUT', ...(body !== undefined ? { body } : {}), ...(queryParams !== undefined ? { queryParams } : {}) });
  }

  /**
   * Helper method for DELETE requests
   */
  private async delete<T>(
    path: string,
    queryParams?: Record<string, string | number | boolean | undefined>
  ): Promise<T> {
    return this.request<T>(path, { method: 'DELETE', ...(queryParams !== undefined ? { queryParams } : {}) });
  }

  // ============================================
  // WORKOUTS
  // ============================================

  /**
   * Get a paginated list of workouts
   */
  async getWorkouts(options?: { page?: number; pageSize?: number }): Promise<any> {
    return this.get<any>('/v1/workouts', options as Record<string, string | number | boolean | undefined>);
  }

  /**
   * Get a single workout by ID
   */
  async getWorkout(workoutId: string): Promise<any> {
    return this.get<any>(`/v1/workouts/${workoutId}`);
  }

  /**
   * Create a new workout
   */
  async createWorkout(workout: any): Promise<any> {
    return this.post<any>('/v1/workouts', workout);
  }

  /**
   * Update an existing workout
   */
  async updateWorkout(workoutId: string, workout: any): Promise<any> {
    return this.put<any>(`/v1/workouts/${workoutId}`, workout);
  }

  /**
   * Get the total count of workouts
   */
  async getWorkoutsCount(): Promise<{ workout_count: number }> {
    return this.get<{ workout_count: number }>('/v1/workouts/count');
  }

  /**
   * Get workout events (updates or deletes) since a given date
   */
  async getWorkoutEvents(options?: { page?: number; pageSize?: number; since?: string }): Promise<any> {
    return this.get<any>('/v1/workouts/events', options as Record<string, string | number | boolean | undefined>);
  }

  // ============================================
  // ROUTINES
  // ============================================

  /**
   * Get a paginated list of routines
   */
  async getRoutines(options?: { page?: number; pageSize?: number }): Promise<any> {
    return this.get<any>('/v1/routines', options as Record<string, string | number | boolean | undefined>);
  }

  /**
   * Get a single routine by ID
   */
  async getRoutine(routineId: string): Promise<{ routine: any }> {
    return this.get<{ routine: any }>(`/v1/routines/${routineId}`);
  }

  /**
   * Create a new routine
   */
  async createRoutine(routine: any): Promise<any> {
    return this.post<any>('/v1/routines', routine);
  }

  /**
   * Update an existing routine
   */
  async updateRoutine(routineId: string, routine: any): Promise<any> {
    return this.put<any>(`/v1/routines/${routineId}`, routine);
  }

  // ============================================
  // EXERCISE TEMPLATES
  // ============================================

  /**
   * Get a paginated list of exercise templates
   */
  async getExerciseTemplates(options?: { page?: number; pageSize?: number }): Promise<any> {
    return this.get<any>('/v1/exercise_templates', options as Record<string, string | number | boolean | undefined>);
  }

  /**
   * Get a single exercise template by ID
   */
  async getExerciseTemplate(exerciseTemplateId: string): Promise<any> {
    return this.get<any>(`/v1/exercise_templates/${exerciseTemplateId}`);
  }

  /**
   * Get exercise history for a specific exercise template
   */
  async getExerciseHistory(
    exerciseTemplateId: string,
    params?: { start_date?: string; end_date?: string }
  ): Promise<any> {
    return this.get<any>(
      `/v1/exercise_history/${exerciseTemplateId}`,
      params as Record<string, string | number | boolean | undefined>
    );
  }

  // ============================================
  // ROUTINE FOLDERS
  // ============================================

  /**
   * Get a paginated list of routine folders
   */
  async getRoutineFolders(options?: { page?: number; pageSize?: number }): Promise<any> {
    return this.get<any>('/v1/routine_folders', options as Record<string, string | number | boolean | undefined>);
  }

  /**
   * Get a single routine folder by ID
   */
  async getRoutineFolder(folderId: string): Promise<any> {
    return this.get<any>(`/v1/routine_folders/${folderId}`);
  }

  /**
   * Create a new routine folder
   */
  async createRoutineFolder(folder: any): Promise<any> {
    return this.post<any>('/v1/routine_folders', folder);
  }

  /**
   * Create a new custom exercise template
   */
  async createExerciseTemplate(exercise: any): Promise<any> {
    return this.post<any>('/v1/exercise_templates', exercise);
  }

  // ============================================
  // USER
  // ============================================

  /**
   * Get the authenticated user's info (id, name, public profile URL)
   */
  async getUserInfo(): Promise<any> {
    return this.get<any>('/v1/user/info');
  }

  // ============================================
  // BODY MEASUREMENTS
  // ============================================

  /**
   * Get a paginated list of body measurements for the authenticated user
   */
  async getBodyMeasurements(options?: { page?: number; pageSize?: number }): Promise<any> {
    return this.get<any>('/v1/body_measurements', options as Record<string, string | number | boolean | undefined>);
  }

  /**
   * Get a single body measurement by date (YYYY-MM-DD)
   */
  async getBodyMeasurement(date: string): Promise<any> {
    return this.get<any>(`/v1/body_measurements/${date}`);
  }

  /**
   * Create a body measurement entry for a given date.
   * The API returns 409 if an entry already exists for that date.
   */
  async createBodyMeasurement(measurement: any): Promise<any> {
    return this.post<any>('/v1/body_measurements', measurement);
  }

  /**
   * Update an existing body measurement entry for a given date (YYYY-MM-DD).
   * All fields are overwritten; omitted fields are set to null.
   */
  async updateBodyMeasurement(date: string, measurement: any): Promise<any> {
    return this.put<any>(`/v1/body_measurements/${date}`, measurement);
  }

  // ============================================
  // WEBHOOK SUBSCRIPTION
  // ============================================

  /**
   * Get the current webhook subscription (url + auth_token), if any
   */
  async getWebhookSubscription(): Promise<any> {
    return this.get<any>('/v1/webhook-subscription');
  }

  /**
   * Create a webhook subscription that notifies your URL when a workout is created
   */
  async createWebhookSubscription(subscription: any): Promise<any> {
    return this.post<any>('/v1/webhook-subscription', subscription);
  }

  /**
   * Delete the current webhook subscription
   */
  async deleteWebhookSubscription(): Promise<any> {
    return this.delete<any>('/v1/webhook-subscription');
  }
}
