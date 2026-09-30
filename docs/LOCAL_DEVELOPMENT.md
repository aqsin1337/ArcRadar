# Local development

ArcRadar runs locally against a **local Supabase stack** (Postgres + Auth in Docker), so you need no
cloud account to develop. A hosted Supabase project is only needed when you deploy to Vercel — see
[`docs/DEPLOYMENT.md`](DEPLOYMENT.md) for that.

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
see; every module is live (nothing is marked "Soon" right now), including AI analyses on an alert,
investigation or indicator page (needs a provider key — see below), response-action tracking, investigation
checklists, and detection rules (admin only). `npm run dev` also serves a component gallery at
<http://localhost:3000/design> (a 404 in production builds).

The **Overview** page is a real dashboard (real counts, charts, recent records); click your name in the
header to reach **Profile** (display name, avatar, password), open to every role. Everyone can read
**Reports** (analysts and administrators can also generate one). Under Administration, analysts and
administrators see **Integrations** (which providers are configured; only an admin may pause one) and their
own **API keys**; **Audit log** and **Settings** (accounts, roles, active status) are admin-only.

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

## Intelligence lookups and live providers (optional)

The IP, domain, URL and hash lookup pages and the vulnerability list work straight away on the built-in
demo dataset (samples such as `198.51.100.23`, `harbor-lights-c2.example`, `8.8.8.8` and the demo CVEs are
offered on each page). To try live providers, add a key to `.env.local` and restart the server:
`VIRUSTOTAL_API_KEY` (IP, domain, URL, hash), `ABUSEIPDB_API_KEY` (IP) or `NVD_API_KEY` (lets an administrator
import a CVE from the vulnerability list). Live lookups are only for analysts and administrators, only for
public values, and are audited; without a key nothing ever leaves your machine. Never commit a key.

## AI features (optional)

The AI card on an alert, investigation or indicator page needs an administrator to do two things on the
**Integrations** page: set a provider's key in `.env.local` (`GROQ_API_KEY` is the quickest to try — a
free account gives you one in a minute) and restart the server, then pick that provider (and, optionally,
a model name) as active. Without either step the card explains why it has nothing to offer instead of
failing; nothing is ever called with no active, configured, enabled provider. Every analysis is rate
limited to 30 per signed-in person per hour, regardless of provider.

## Alerts, investigations and threat intelligence

These pages work from the seed (15 alerts, 6 investigations, 5 actors, 4 campaigns, 6 malware families, 15
ATT&CK techniques, all labelled demo data). What each demo user can do there:

| Role    | Alerts and investigations                                          | Threat actors, campaigns, malware, MITRE | Indicators                   |
| ------- | ------------------------------------------------------------------ | ---------------------------------------- | ---------------------------- |
| viewer  | read only                                                          | read only                                | read only                    |
| analyst | create, acknowledge, resolve, assign, open and work investigations | read only                                | create, edit, link, relate   |
| admin   | everything, including deleting alerts and investigations           | create, edit, delete                     | everything, including delete |

The end-to-end tests create their own records (titles start with `E2E`) and remove them afterwards with the
service role. Threat intelligence you add by hand is saved as `local` data, never as demo or external.

## Telemetry (sensor data)

The **Telemetry** page lists each source with its status, the machines (assets) that report, and the latest
events. From the seed it shows demo feeds (labelled "Demo feed", never "receiving") and four demo machines; the
Wazuh card reads "No events yet" until something is delivered. You can try the whole pipeline without a
Wazuh Manager:

```powershell
# 1. an administrator makes an ingest key (printed once; the password comes from the environment)
$env:ARCRADAR_EMAIL = "admin@arcradar.test"; $env:ARCRADAR_PASSWORD = "ArcRadar-Demo-1!"
npm run apikey:create -- --url http://localhost:3000 --name "Local trial" --days 7
# 2. send fictional Wazuh alerts with it (manager "sample-manager", agents SAMPLE-*)
npm run ingest:sample -- --url http://localhost:3000 --key arc_...
```

The Wazuh card turns to "Receiving", alerts of level 7 and up appear on **Alerts** (origin "External provider"),
and re-sending with `--replay` creates nothing new. This data is stored like real telemetry: remove it from the
database when you are done (`delete` the `wazuh` rows of `alerts`, `events`, `assets`, `indicators`, and the
key from `api_keys`), or run `npm run db:reset`. Connecting a real Manager: `docs/WAZUH_INTEGRATION.md`.
The end-to-end tests make their own keys and telemetry (names start with `E2E-TEL`) and remove them afterwards.

## Demo users (local seed only)

| Email                   | Role    | Password           |
| ----------------------- | ------- | ------------------ |
| `admin@arcradar.test`   | admin   | `ArcRadar-Demo-1!` |
| `analyst@arcradar.test` | analyst | `ArcRadar-Demo-1!` |
| `viewer@arcradar.test`  | viewer  | `ArcRadar-Demo-1!` |

These exist only in your local database. `supabase/seed.sql` never runs against a hosted project, and
these credentials must never be used in production. All seeded records are marked `origin = 'demo'`.

## Commands

| Command                             | What it does                                                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `npm run dev` / `build` / `start`   | Next.js dev server / production build / production server                                                                                                                                              |
| `npm run lint`, `typecheck`, `test` | ESLint, `next typegen` + `tsc`, Vitest                                                                                                                                                                 |
| `npm run format` / `format:check`   | Prettier                                                                                                                                                                                               |
| `npm run db:start` / `db:stop`      | Start / stop the local Supabase containers (data is kept)                                                                                                                                              |
| `npm run db:reset`                  | Rebuild the local database from migrations + seed                                                                                                                                                      |
| `npm run db:test`                   | Database security and constraint tests (stack must be running)                                                                                                                                         |
| `npm run db:types`                  | Regenerate `src/types/database.ts` from the local schema                                                                                                                                               |
| `npm run db:env`                    | Refresh Supabase values in `.env.local`                                                                                                                                                                |
| `npm run api:smoke`                 | End-to-end API checks (app + local stack must be running)                                                                                                                                              |
| `npm run e2e`                       | Browser tests in Chrome (local stack up, `npm run build` first)                                                                                                                                        |
| `npm run check:contrast`            | WCAG contrast check of the design tokens, both themes                                                                                                                                                  |
| `npm run apikey:create`             | Make an ingest API key as an administrator (`--url`, `--name`)                                                                                                                                         |
| `npm run ingest:sample`             | Send fictional Wazuh alerts to a running app with a key                                                                                                                                                |
| `npm run import:mitre`              | Load the MITRE ATT&CK catalog (techniques, threat actors, malware, campaigns) from the official STIX file; safe to rerun. Local by default, `--url` + `SUPABASE_SERVICE_ROLE_KEY` for a hosted project |
| `npm run bootstrap:admin`           | Promote an existing account to admin directly (for a fresh hosted deployment with no admin yet — see `docs/DEPLOYMENT.md`; locally the seed already gives you one)                                     |
| `npx supabase migration new <name>` | Create a new empty migration file                                                                                                                                                                      |

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
- **`npm run format:check` fails on every file on Windows:** the files were checked out with CRLF line endings
  (Git for Windows defaults to `core.autocrlf=true`) and Prettier wants LF. The repo's `.gitattributes` forces LF,
  so a fresh clone is fine; an older clone needs `git config --local core.autocrlf input` and `npm run format`, or
  simply a fresh clone. `docs/HANDOFF_PROMPT.md` and `docs/ORIGINAL_PROMPT.md` keep the original prompt verbatim
  and are excluded from Prettier.
