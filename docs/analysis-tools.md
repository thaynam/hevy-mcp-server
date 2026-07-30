# Analysis Tools — Integration Guide (FitCrew)

The **analysis tools** aggregate raw Hevy data **server-side** so a consumer
(like FitCrew) asks one question and gets a ready-made summary — instead of
paging through dozens of measurements/workouts and doing the math client-side.

| Tool | Answers | Default window |
|---|---|---|
| `get_body_progress` | How are weight / body-fat / circumferences trending? | 8 weeks |
| `get_training_summary` | How consistent is training, and what's the load? | 4 weeks |
| `get_progression_deltas` | For each exercise this session, how does it compare to its last time? | most recent workout |
| `get_window_progression` | For every exercise trained in the window, how does it compare to its last time? | 1 week |
| `get_personal_records` | What are the maxima per exercise? | all scanned history |
| `compare_workouts` | How do two specific workouts differ? | two IDs |
| `get_previous_routine_instance` | What was the previous run of this routine? | a routine ID |
| `get_muscle_balance` | How are sets/volume split across muscle groups? | 4 weeks |

> **Self-documenting:** every tool is registered with a `description` and an
> `outputSchema`, so `tools/list` already returns the human description **and**
> the JSON schema of the structured output. An MCP-aware client (CrewAI) sees
> this automatically. This doc is the human-facing companion.

---

## The boundary: facts here, judgment in the coach

**This MCP is a facts layer. The AI coach is the judgment layer.** The MCP is
multi-user and does **not** know each user's phase (cut / bulk / maintenance),
and the same number means opposite things by phase — a load drop is
*preservation* in a cut and *regression* in a bulk. So these tools return
**context-independent numbers only**:

- No verdicts, labels, good/bad, or ▲▼ direction arrows.
- Exercises are keyed by **`exercise_template_id`**, never by name.
- **Warmup sets are excluded** from every aggregation (sets, volume, top set…).
- Epley estimated 1RM (`weight × (1 + reps/30)`) is provided — it's
  phase-independent arithmetic, a fact.

The coach applies meaning on top. Don't expect the MCP to tell you whether a
delta is "good".

---

## Auth & endpoint

- **Endpoint:** `POST https://hevy-mcp-server.mcp-tools.workers.dev/mcp` (MCP
  Streamable HTTP).
- **Auth (FitCrew backend → server):** send the user's Hevy API key in the
  `X-Hevy-API-Key` header (the fast-path that bypasses OAuth; use it for
  backend-to-server calls).

```
X-Hevy-API-Key: <the user's Hevy API key>
Content-Type: application/json
Accept: application/json, text/event-stream
```

Every tool returns two things:

- `content` — human-readable text (neutral, factual).
- `structuredContent` — typed JSON matching the tool's `outputSchema`. **Use this
  for logic/decisions.**

**Shared conventions**

- **Prefer `structuredContent`** for any logic.
- **Scan cap:** history tools read up to **20 pages** (~200 workouts/measurements)
  by default. If more exist, `truncated: true` (in `structuredContent`, not just
  the text). The history tools (`get_progression_deltas`, `get_personal_records`,
  `get_previous_routine_instance`, `get_muscle_balance`) accept **`max_pages`**
  (default 20, up to 100) to scan deeper — useful for high-frequency loggers
  where a real record or the correct prior session can be older than 200 workouts.
- **Date window** is by calendar day (`YYYY-MM-DD`) from the server's current date.
- **Errors vs. empty:** an empty result (count 0, `previous: null`, `anchor: null`)
  is normal, not an error. Real failures (bad key, Hevy down) return `isError: true`.

---

## `get_body_progress`

Trend of weight, body-fat and every circumference over the last N weeks.

**Input:** `weeks` (integer, default `8`, 1–52).

```jsonc
{
  "since": "2025-07-29",
  "entryCount": 5,
  "firstDate": "2025-10-27",       // omitted if entryCount == 0
  "lastDate": "2026-02-28",
  "metrics": [                     // one entry per metric that has data
    {
      "field": "weight_kg",
      "first": 88, "last": 86.8,
      "change": -1.2,              // last − first (raw)
      "count": 4,
      "firstDate": "2025-10-27",
      "lastDate": "2026-02-28"
    }
    // ... waist, fat_percent, chest_cm, left_thigh, etc.
  ]
}
```

A metric with no data in the window is **absent** from `metrics` (no fake zeros).

---

## `get_training_summary`

Training load / consistency over the last N weeks.

**Input:** `weeks` (integer, default `4`, 1–52).

```jsonc
{
  "since": "2025-07-29",
  "workoutCount": 140,
  "activeDays": 140,               // distinct days with a workout
  "totalExercises": 918,
  "effectiveSets": 2278,           // NON-warmup sets
  "totalVolumeKg": 1209123.9,      // Σ(weight_kg × reps) over effective sets
  "avgWorkoutsPerWeek": 2.69,      // workoutCount / weeks
  "firstDate": "2025-10-22",       // omitted if workoutCount == 0
  "lastDate": "2026-07-28"
}
```

> **Changed:** the field is now `effectiveSets` (was `totalSets`) and both
> `effectiveSets` and `totalVolumeKg` **exclude warmup sets**.

---

## `get_progression_deltas`

For each exercise in a session, the raw diff vs. the **previous occurrence of the
same `exercise_template_id`** — found by scanning earlier workouts (skipping the
sessions in between that trained other muscle groups).

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `workout_id` | string | most recent workout | The session to analyze. |
| `history_depth` | integer | `1` | 1–20. When `> 1`, each exercise also gets an `occurrences` array: the last N occurrences of that `template_id` (current + priors, most recent first) — a multi-session view without chaining calls client-side. |
| `max_pages` | integer | `20` | 1–100. Scan depth (~10 workouts/page). |

```jsonc
{
  "session": { "workout_id": "…", "date": "2026-07-28", "exercise_count": 6 },
  "exercises": [
    {
      "exercise_template_id": "D04AC939",
      "exercise_title": "Bench Press (Barbell)",   // convenience, not a key
      "current": {
        "workout_id": "…", "date": "2026-07-28",
        "effective_sets": 3,
        "total_volume_kg": 1500,
        "total_reps": 15,
        "max_weight_kg": 100,
        "best_estimated_1rm_kg": 116.7,
        "top_set": { "weight_kg": 100, "reps": 5, "rpe": 8 }
      },
      "previous": { /* same shape */ },   // null on first-ever occurrence
      "delta": {                          // current − previous, raw; null if previous null
        "effective_sets": 0, "total_volume_kg": 37.5, "total_reps": 0,
        "max_weight_kg": 2.5, "best_estimated_1rm_kg": 2.9,
        "top_set_weight_kg": 2.5, "top_set_reps": 0,
        "top_set_rpe": 1.5                // RPE change on the top set; null if either side lacks RPE
      },
      "occurrences": [ /* current + N priors, same shape as current — only when history_depth > 1 */ ]
    }
  ],
  "scanned_workouts": 140,
  "exercises_without_previous": 0,
  "truncated": false
}
```

Bodyweight/duration exercises: `top_set`/`max_weight_kg`/`best_estimated_1rm_kg`
come back `null`; `effective_sets`/`total_reps` are still valid.

`top_set_rpe` is the raw RPE difference at the top set — e.g. same load × reps
with rising RPE is a fatigue **fact** the coach can interpret. It is `null`
(never zero) when either side has no RPE logged.

---

## `get_window_progression`

The window-wide version of `get_progression_deltas`: **every** exercise trained
at least once in the last N weeks (legs + push + pull days together), each vs.
the previous occurrence of its own `exercise_template_id` — in **one call and
one server-side scan**, instead of calling `get_progression_deltas` per
workout and merging client-side. `get_progression_deltas` is unchanged; use it
when you want exactly one session.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `weeks` | integer | `1` | 1–52. Window = today − `weeks` (calendar day, like the other window tools). |
| `history_depth` | integer | `1` | 1–20. Same meaning as in `get_progression_deltas` (per-exercise `occurrences` array). |
| `max_pages` | integer | `20` | 1–100. Scan depth (~10 workouts/page). |

**Semantics (per exercise, keyed by `exercise_template_id`)**

- Every exercise trained ≥ 1× in the window gets **one** entry (deduplicated —
  not repeated per session).
- `current` = its most recent occurrence **inside** the window.
- `previous` = the occurrence immediately before that one — which may fall
  inside **or before** the window; `null` on first-ever occurrence.
- `delta` / `occurrences` / all per-exercise math (effective sets, volume, Epley
  1RM, `top_set` with weight/reps/rpe, `top_set_rpe` null when either side lacks
  RPE) are **identical** to `get_progression_deltas`.

```jsonc
{
  "window": {
    "since": "2026-07-23", "weeks": 1,
    "sessionCount": 5,
    "workoutIds": ["…", "…"]           // most recent first
  },
  "exercises": [                        // one entry per template, most recent current first
    {
      "exercise_template_id": "D04AC939",
      "exercise_title": "Bench Press (Barbell)",
      "current":  { /* same occurrence shape as get_progression_deltas */ },
      "previous": { /* same shape; null on first-ever occurrence */ },
      "delta":    { /* current − previous, raw; null if previous null */ },
      "occurrences": [ /* current + N priors — only when history_depth > 1 */ ]
    }
  ],
  "scanned_workouts": 140,
  "exercises_without_previous": 0,
  "truncated": false
}
```

An empty window is a normal result (`exercises: []`, `sessionCount: 0`), not an
error.

---

## `get_personal_records`

Per exercise (by `template_id`), the maxima across scanned workouts.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `exercise_template_id` | string | all exercises | Restrict to one exercise. |
| `max_pages` | integer | `20` | 1–100. Scan depth (~10 workouts/page). |

> ⚠️ **Records are maxima over the scanned window** (`scanned_workouts`), not
> absolute all-time records. When `truncated: true`, an older, larger record may
> exist — raise `max_pages` (or say "best in the last N workouts", not "all-time
> PR") for high-frequency loggers.

```jsonc
{
  "records": [
    {
      "exercise_template_id": "…",
      "exercise_title": "Iso-Lateral High Row (Machine)",
      "max_weight_kg":       { "value": 90,  "weight_kg": 90, "reps": 12, "date": "2026-07-28", "workout_id": "…" },
      "best_estimated_1rm_kg": { "value": 126, "weight_kg": 90, "reps": 12, "date": "2026-07-28", "workout_id": "…" },
      "max_reps":            { "value": 15,  "weight_kg": 80, "reps": 15, "date": "2026-07-20", "workout_id": "…" }
    }
  ],
  "scanned_workouts": 140,
  "truncated": false
}
```

Any record field is `null` if the exercise has no qualifying (effective) set for
it (e.g. `max_weight_kg` is null for a bodyweight-only exercise).

---

## `compare_workouts`

Raw component-wise diff of **two** workouts. Components are returned separately —
never a single score (tonnage alone misleads), never a "shorter/worse" label.

**Input:** `workout_id_a` (string, required), `workout_id_b` (string, required).

```jsonc
{
  "a": { "workout_id": "…", "date": "2026-07-28", "tonnage_kg": 10740,
         "effective_sets": 24, "duration_seconds": 3600,
         "exercise_template_ids": ["…", "…"] },
  "b": { /* same shape */ },
  "delta": { "tonnage_kg": 1948, "effective_sets": 2, "duration_seconds": 677 },
  "exercises": {
    "in_both":   [ { "exercise_template_id": "…", "exercise_title": "…" } ],
    "only_in_a": [ … ],
    "only_in_b": [ … ]
  }
}
```

`tonnage_kg = Σ(weight_kg × reps)` over effective sets. `duration_*` is `null`
when a timestamp is missing. Presence keyed by `template_id`. Pair with
`get_previous_routine_instance` to find the prior instance of a routine.

---

## `get_previous_routine_instance`

Finds instances of a `routine_id` and returns the anchor instance and the one
before it — so the caller can feed both IDs to `compare_workouts`. Matching the
"same session" **without** a routine is fuzzy/user-specific and is left to the
caller.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `routine_id` | string | — | Required. |
| `before_workout_id` | string | most recent instance | Anchor; returns the instance before it. |
| `max_pages` | integer | `20` | 1–100. Scan depth (~10 workouts/page). |

```jsonc
{
  "routine_id": "…",
  "anchor":   { "workout_id": "…", "date": "2026-07-28" },  // or null
  "previous": { "workout_id": "…", "date": "2026-07-20" },  // or null
  "total_instances": 7,
  "scanned_workouts": 140,
  "truncated": false
}
```

---

## `get_muscle_balance`

Distribution of effective sets and volume per **primary muscle group** over the
last N weeks — numbers only, never a "balanced/unbalanced" verdict. Joins
workouts to the exercise catalog by `template_id`.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `weeks` | integer | `4` | 1–52. Window = today − `weeks`. |
| `include_secondary` | boolean | `false` | When `true`, also returns a **separate** `by_muscle_group_secondary` block. |
| `max_pages` | integer | `20` | 1–100. Scan depth (~10 workouts/page). |

```jsonc
{
  "since": "2025-07-29",
  "workouts_counted": 140,
  "by_muscle_group": [               // PRIMARY muscle group; sorted by effective_sets desc
    { "muscle_group": "chest",     "effective_sets": 349, "total_volume_kg": 205723.5, "exercise_count": 120 },
    { "muscle_group": "shoulders", "effective_sets": 332, "total_volume_kg": 113401.4, "exercise_count": 110 }
    // ...
  ],
  "unmapped_exercises": 0,               // occurrences whose template isn't in the catalog
  "unmapped_exercise_template_ids": [],  // the distinct missing template_ids (so the client can re-cache its muscle map)
  "by_muscle_group_secondary": [         // only when include_secondary: true — same shape,
    // counted where the muscle is a SECONDARY mover
  ],
  "truncated": false
}
```

**Secondary volume:** exercises like bench press or rows also work triceps/biceps
as secondary movers, so arm volume is under-counted in the primary-only view. With
`include_secondary: true` you get both distributions **separately** — the same
set is attributed to its primary group in `by_muscle_group` and to each of its
secondary groups in `by_muscle_group_secondary`. They are **never summed**, and
no 0.5-credit convention is baked in: the coach decides how (or whether) to
credit secondary work.

---

## Calling from Python (reference)

Using the official MCP Python SDK (reliable, low-level):

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "https://hevy-mcp-server.mcp-tools.workers.dev/mcp"

async def call_tool(hevy_api_key: str, name: str, args: dict) -> dict:
    headers = {"X-Hevy-API-Key": hevy_api_key}
    async with streamablehttp_client(URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(name, args)
            return result.structuredContent  # typed dict as documented above

# e.g. await call_tool(key, "get_progression_deltas", {})
#      await call_tool(key, "get_muscle_balance", {"weeks": 8})
```

### With CrewAI

CrewAI can auto-load these as agent tools via its MCP adapter (check the API
against your installed `crewai-tools` version):

```python
from crewai_tools import MCPServerAdapter

server_params = {
    "url": "https://hevy-mcp-server.mcp-tools.workers.dev/mcp",
    "transport": "streamable-http",
    "headers": {"X-Hevy-API-Key": hevy_api_key},
}

with MCPServerAdapter(server_params) as tools:
    # `tools` includes all Hevy tools, each with the description + output schema.
    agent = Agent(role="Coach", tools=tools, ...)
```

---

## Suggested usage patterns

- **Check-in opener:** `get_training_summary(weeks=4)` + `get_body_progress(weeks=8)`
  so the coach knows consistency and weight/waist trend without asking.
- **Session review:** `get_progression_deltas()` right after a workout, then the
  coach interprets each delta against the user's phase.
- **Multi-session trend / fatigue check:** `get_progression_deltas(history_depth=3)`
  to see the last 3 occurrences of each exercise in one call — e.g. load flat
  while `top_set_rpe` rises across sessions.
- **Week in review:** `get_window_progression(weeks=1)` — every exercise trained
  this week vs. its own last time, in one call; no per-workout calls + merge.
- **Routine comparison:** `get_previous_routine_instance(routine_id)` → feed
  `anchor` + `previous` workout IDs into `compare_workouts`.
- **Programming check:** `get_muscle_balance(weeks=8)` for the raw split; the
  coach decides if it fits the user's goal.
- **Celebrating:** `get_personal_records()` to surface maxima the coach can call out.
