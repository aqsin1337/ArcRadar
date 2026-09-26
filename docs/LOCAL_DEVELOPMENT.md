# Local development

ArcRadar runs locally against a **local Supabase stack** (Postgres + Auth in Docker), so you need no
cloud account to develop. A hosted Supabase project is only needed when you deploy to Vercel.

## Requirements

- Node.js 20.19+ (24 LTS is installed on this machine) and npm
- Docker Desktop, **running**
- nginx (optional, only for the local reverse-proxy setup below)

## First-time setup

```bash
npm install
npm run db:start   # starts local Supabase; the first run downloads several GB of images
npm run db:reset   # applies supabase/migrations and the demo seed (supabase/seed.sql)
npm run db:env     # writes the local Supabase URL and keys into .env.local
npm run dev        # http://localhost:3000
```

Check that everything is connected: <http://localhost:3000/api/health> should answer
`{"success":true,"data":{"app":"arcradar","status":"ok","supabase":"ok"},"error":null}`.

Local Supabase addresses: API `http://127.0.0.1:54321`, Studio (browse tables) `http://127.0.0.1:54323`,
test mailbox `http://127.0.0.1:54324` (password-recovery and confirmation emails land here).

## Using the app

Open <http://localhost:3000>. It sends you to the sign-in page; on the local stack the page shows
Admin / Analyst / Viewer buttons that fill in a demo account (controlled by `NEXT_PUBLIC_DEMO_LOGINS=true`,
which `npm run db:env` sets; leave it empty anywhere else). Signed in, the sidebar shows what the role may
see; entries marked "Soon" are modules built in later phases. `npm run dev` also serves a component gallery at
<http://localhost:3000/design> (a 404 in production builds).

## Trying the API

The JSON API can be used on its own. With the app running:

```bash
curl -i -c jar.txt -X POST http://localhost:3000/api/auth/login \
  -H "content-type: application/json" \
  -d '{"email":"admin@arcradar.test","password":"ArcRadar-Demo-1!"}'
curl -b jar.txt http://localhost:3000/api/auth/me
curl -b jar.txt "http://localhost:3000/api/audit-logs?page_size=5"
```

`npm run api:smoke` runs the full set of checks. Endpoints and conventions: `docs/API.md`. Changes to
`supabase/config.toml` (auth settings, redirect URLs) need `npm run db:stop` then `npm run db:start`.

## Demo users (local seed only)

| Email                   | Role    | Password           |
| ----------------------- | ------- | ------------------ |
| `admin@arcradar.test`   | admin   | `ArcRadar-Demo-1!` |
| `analyst@arcradar.test` | analyst | `ArcRadar-Demo-1!` |
| `viewer@arcradar.test`  | viewer  | `ArcRadar-Demo-1!` |

These exist only in your local database. `supabase/seed.sql` never runs against a hosted project, and
these credentials must never be used in production. All seeded records are marked `origin = 'demo'`.

## Commands

| Command                             | What it does                                                    |
| ----------------------------------- | --------------------------------------------------------------- |
| `npm run dev` / `build` / `start`   | Next.js dev server / production build / production server       |
| `npm run lint`, `typecheck`, `test` | ESLint, `next typegen` + `tsc`, Vitest                          |
| `npm run format` / `format:check`   | Prettier                                                        |
| `npm run db:start` / `db:stop`      | Start / stop the local Supabase containers (data is kept)       |
| `npm run db:reset`                  | Rebuild the local database from migrations + seed               |
| `npm run db:test`                   | Database security and constraint tests (stack must be running)  |
| `npm run db:types`                  | Regenerate `src/types/database.ts` from the local schema        |
| `npm run db:env`                    | Refresh Supabase values in `.env.local`                         |
| `npm run api:smoke`                 | End-to-end API checks (app + local stack must be running)       |
| `npm run e2e`                       | Browser tests in Chrome (local stack up, `npm run build` first) |
| `npm run check:contrast`            | WCAG contrast check of the design tokens, both themes           |
| `npx supabase migration new <name>` | Create a new empty migration file                               |

## Changing the database

1. `npx supabase migration new describe_the_change`, then write SQL in the new file. Never edit a
   migration that has already been applied elsewhere; add a new one.
2. `npm run db:reset`, then `npm run db:types`, then `npm run db:test`.
3. New tables must enable RLS and get policies in the same migration. `npm run db:test` fails if a
   `public` table has no RLS or no policy.

## nginx reverse proxy (optional)

nginx listens on `http://localhost:8080` and forwards to Next.js on port 3000. It is for local,
production-like testing only; Vercel does not use it.

```powershell
npm run build; npm start                       # or npm run dev, in one terminal
powershell -File scripts/nginx.ps1 start       # http://localhost:8080
powershell -File scripts/nginx.ps1 stop
```

`scripts/nginx.ps1` also supports `test` (validate the config) and `reload`. Config:
`deploy/nginx/nginx.conf`. Logs: `deploy/nginx/runtime/logs/`.

## Troubleshooting

- **`npm run db:start` fails or hangs:** start Docker Desktop and wait until it says it is running.
- **Low memory:** the local stack needs about 1-2 GB. Run `npm run db:stop` when you are not using it.
- **`/api/health` says `not_configured` or `unreachable`:** run `npm run db:start`, then `npm run db:env`,
  then restart `npm run dev`.
- **Port already in use:** something else uses 3000, 8080 or 5432x. Stop it or change the port.
- **OneDrive:** this folder lives under OneDrive. Keep OneDrive stopped while developing so it does not
  sync `node_modules` and `.next`.
- **`node` not found in Git Bash:** open a new terminal after installing Node, or use PowerShell.
