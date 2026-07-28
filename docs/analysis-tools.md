# Analysis Tools — Integration Guide (FitCrew)

The **analysis tools** aggregate raw Hevy data **server-side** so a consumer
(like FitCrew) asks one question and gets a ready-made summary — instead of
paging through dozens of measurements/workouts and doing the math client-side.

There are two:

| Tool | Answers | Default window |
|---|---|---|
| `get_body_progress` | How are weight / body-fat / circumferences trending? | 8 weeks |
| `get_training_summary` | How consistent is training, and what's the load? | 4 weeks |

> **Self-documenting:** every tool is registered with a `description` and an
> `outputSchema`, so `tools/list` already returns the human description **and**
> the JSON schema of the structured output. An MCP-aware client (CrewAI) sees
> this automatically. This doc is the human-facing companion.

---

## Auth & endpoint

- **Endpoint:** `POST https://hevy-mcp-server.mcp-tools.workers.dev/mcp` (MCP
  Streamable HTTP).
- **Auth (FitCrew backend → server):** send the user's Hevy API key in the
  `X-Hevy-API-Key` header. This is the fast-path that bypasses the OAuth flow;
  use it for backend-to-server calls.

```
X-Hevy-API-Key: <the user's Hevy API key>
Content-Type: application/json
Accept: application/json, text/event-stream
```

Every tool returns two things:

- `content` — human-readable text (good to drop straight into a prompt/message).
- `structuredContent` — typed JSON matching the tool's `outputSchema`. **Use this
  for logic/decisions.**

---

## `get_body_progress`

Trend of weight, body-fat and every circumference over the last N weeks.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `weeks` | integer | `8` | 1–52. Window = today − `weeks`. |

**`structuredContent`**

```jsonc
{
  "since": "2025-07-29",          // window lower bound (YYYY-MM-DD)
  "entryCount": 5,                 // measurements in the window
  "firstDate": "2025-10-27",       // omitted if entryCount == 0
  "lastDate": "2026-02-28",
  "metrics": [                     // one entry per metric that has data
    {
      "field": "weight_kg",
      "first": 88, "last": 86.8,
      "change": -1.2,              // last - first (negative = decreased)
      "count": 4,
      "firstDate": "2025-10-27",
      "lastDate": "2026-02-28"
    }
    // ... waist, fat_percent, chest_cm, left_thigh, etc.
  ]
}
```

A metric with no data in the window is simply **absent** from `metrics` (no fake
zeros).

**Good for:** answering "how's my progress?" without asking the user their
weight — read `weight_kg.change`, `waist.change`, etc.

---

## `get_training_summary`

Training load / consistency over the last N weeks.

**Input**

| Field | Type | Default | Notes |
|---|---|---|---|
| `weeks` | integer | `4` | 1–52. Window = today − `weeks`. |

**`structuredContent`**

```jsonc
{
  "since": "2025-07-29",
  "workoutCount": 140,
  "activeDays": 140,               // distinct days with a workout
  "totalExercises": 918,
  "totalSets": 2552,
  "totalVolumeKg": 1274943.4,      // sum of (weight_kg × reps) across sets
  "avgWorkoutsPerWeek": 2.69,      // workoutCount / weeks
  "firstDate": "2025-10-22",       // omitted if workoutCount == 0
  "lastDate": "2026-07-28"
}
```

- Volume counts a set only when both `weight_kg` **and** `reps` are numeric.

**Good for:** adherence checks ("you trained 2.7×/week over the last 4 weeks")
and deciding whether to progress or deload.

---

## Things that matter for integration

- **Prefer `structuredContent` over text** for any logic.
- **Scan cap:** each tool reads up to **20 pages** (~200 measurements / ~200
  workouts). If the window has more, the text includes a note that older data
  may exist. Fine for typical volumes.
- **Date window** is computed by calendar day (`YYYY-MM-DD`) from the server's
  current date.
- **Errors vs. empty:** an empty window is a normal result (`entryCount` /
  `workoutCount` = 0), not an error. Real failures (bad key, Hevy down) come back
  with `isError: true`.

---

## Calling from Python (reference)

Using the official MCP Python SDK (reliable, low-level):

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = "https://hevy-mcp-server.mcp-tools.workers.dev/mcp"

async def body_progress(hevy_api_key: str, weeks: int = 8) -> dict:
    headers = {"X-Hevy-API-Key": hevy_api_key}
    async with streamablehttp_client(URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get_body_progress", {"weeks": weeks})
            return result.structuredContent  # typed dict as documented above
```

`call_tool("get_training_summary", {"weeks": 4})` works the same way.

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
    # `tools` now includes get_body_progress, get_training_summary, and the
    # other 25 Hevy tools, each with the description + output schema above.
    agent = Agent(role="Coach", tools=tools, ...)
```

---

## Suggested usage patterns

- **Check-in opener:** call `get_training_summary(weeks=4)` + `get_body_progress(weeks=8)`
  at the start of a conversation so the coach already knows training consistency
  and weight/waist trend — without asking the user anything.
- **Weekly report:** call both with `weeks=1`.
- **Progress question:** `get_body_progress` on demand and comment on the sign of
  each `change`.
