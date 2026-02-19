# Hevy MCP Server

MCP server for the [Hevy](https://www.hevyapp.com/) API, built on Cloudflare Workers.
It exposes Hevy data and actions as MCP tools for AI clients, with OAuth 2.1 auth and per-user encrypted API key storage.

## What it provides

- 17 MCP tools across workouts, routines, exercise templates, exercise history, and routine folders
- Streamable HTTP transport at `/mcp` (primary)
- Legacy SSE transport at `/sse` (compatibility)
- OAuth 2.1 endpoints (`/authorize`, `/token`, `/register`) for MCP clients
- Setup UI at `/setup` for each user to save their own Hevy API key

## Tool list

- **Workouts:** `get_workouts`, `get_workout`, `create_workout`, `update_workout`, `get_workouts_count`, `get_workout_events`
- **Routines:** `get_routines`, `get_routine`, `create_routine`, `update_routine`
- **Exercise templates/history:** `get_exercise_templates`, `get_exercise_template`, `create_exercise_template`, `get_exercise_history`
- **Routine folders:** `get_routine_folders`, `get_routine_folder`, `create_routine_folder`

## Quick start (local)

### 1) Install

```bash
npm install
```

### 2) Configure env

```bash
cp .dev.vars.example .dev.vars
```

Set values in `.dev.vars`:

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `COOKIE_ENCRYPTION_KEY` (generate with `openssl rand -hex 32`)

### 3) Run

```bash
npm run dev
```

Server URLs:

- MCP: `http://localhost:8787/mcp`
- Setup page: `http://localhost:8787/setup`
- Health: `http://localhost:8787/health`

### 4) Add your Hevy API key

Open `/setup`, sign in with GitHub, and paste your Hevy API key from:
https://hevy.com/settings?developer

## Deploy

1. Authenticate Wrangler:

```bash
npx wrangler login
```

2. Set production secrets:

```bash
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put COOKIE_ENCRYPTION_KEY
```

3. Deploy:

```bash
npm run deploy
```

Then complete account setup at `https://<your-worker-domain>/setup`.

## Connect from an MCP client

Use your deployed MCP endpoint:

`https://<your-worker-domain>/mcp`

Your client must support OAuth 2.1 MCP flows (discovery, authorization code, token exchange).

## Development commands

- `npm run dev` / `npm start` - local Wrangler dev server
- `npm run type-check` - TypeScript strict type check
- `npm run test:run` - run tests once
- `npm test` - watch mode tests
- `npm run format` - format with Biome
- `npm run lint:fix` - lint autofix with Biome

## Architecture (short)

- `src/index.ts` - exports app + Durable Object
- `src/app.ts` - middleware and route composition
- `src/mcp-agent.ts` - MCP tool registration
- `src/lib/client.ts` - Hevy API client wrapper
- `src/github-handler.ts` - OAuth + setup UI + auth endpoints

## Notes

- Hevy API keys are not hardcoded and are stored encrypted per user in KV.
- `/mcp` is the preferred transport; `/sse` remains for compatibility.
- This project is not affiliated with Hevy.

## License

Unlicense. See [LICENSE](LICENSE).
