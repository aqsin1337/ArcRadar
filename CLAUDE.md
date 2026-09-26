# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Project

**ArcRadar** — a cybersecurity intelligence and threat-monitoring platform (indicators/IOCs, IP/domain/URL/hash intelligence, vulnerabilities, threat actors, alerts, investigations, reports, API keys, audit log). Holberton portfolio project. Production target: Vercel + Supabase. State, decisions and per-phase handoff notes live in `docs/ARCRADAR_PROGRESS.md`; how to run it is in `docs/LOCAL_DEVELOPMENT.md`.

Stack: Next.js 16 (App Router, `src/` layout) + TypeScript, Tailwind 4, Supabase (Postgres + Auth), Zod, Vitest. Next 16 renamed middleware to `proxy` (`src/proxy.ts`); `cookies()` is async. Read `node_modules/next/dist/docs/` before using Next APIs.

## Commands

```bash
npm run dev | build | start        # Next.js
npm run lint | typecheck | test    # typecheck runs `next typegen` first (LayoutProps etc. are generated)
npm run format | format:check      # Prettier (printWidth 100)
npx vitest run tests/env.test.ts   # single test file (or add -t "name" to filter)
npm run db:start | db:stop         # local Supabase in Docker (Docker Desktop must be running)
npm run db:reset                   # rebuild local DB from supabase/migrations + supabase/seed.sql
npm run db:test                    # SQL security/constraint tests in supabase/tests (stack must be running)
npm run db:types                   # regenerate src/types/database.ts after any schema change
npm run db:env                     # write local Supabase URL/keys into .env.local
npm run e2e                        # Playwright in real Chrome (local Supabase up + `npm run build` first); needs the built app, starts `npm start` itself
npm run check:contrast             # WCAG contrast of design tokens (run after editing colors in globals.css)
npm run api:smoke                  # end-to-end API checks (app running + local Supabase up); SMOKE_BASE_URL=http://localhost:8080 to go through nginx
powershell -File scripts/nginx.ps1 test|start|stop|reload   # local nginx :8080 -> Next.js :3000
```

Schema change loop: `npx supabase migration new <name>` → write SQL → `npm run db:reset` → `npm run db:types` → `npm run db:test`. Never edit an applied migration; add a new one. New tables need RLS and policies in the same migration (the DB test enforces it).

Windows: `node` is not on Git Bash's PATH, and each PowerShell call starts fresh. Prefix PowerShell with `$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')`. The project sits under OneDrive: keep OneDrive stopped during installs and builds.

## Architecture (the parts that span files)

- **Layers (built in Phase 2):** Route Handler → auth/authz guard → Zod validation → service layer → repository (Supabase) / provider adapter. Export handlers wrapped in `publicRoute` / `protectedRoute({ permissions })` (`src/lib/api/handler.ts`): they do the origin check, session + permission guard, error mapping and the `{ success, data, error }` envelope. Throw `apiErrors.*`; use `unwrap()` around queries. Recipe and error codes: `docs/API.md`.
- **Frontend:** pages under `src/app/(app)/` are guarded by the layout (`getPageAuth()`, server-verified); `(auth)` holds the signed-out pages; `proxy.ts` only redirects cookie-less visitors. Never wrap `cookies()`/`redirect()` in a bare try/catch without `unstable_rethrow(error)`. UI is Tailwind with semantic tokens from `globals.css` (never raw hex or Tailwind palette colors), primitives in `src/components/ui/` (gallery at `/design` in dev), nav in `src/lib/nav.ts`. Error boundaries take `retry`, not `reset`, in this Next version. Every record shown to users must carry its provenance badge. Forms call the JSON API with `apiFetch`.
- **Records (indicators are the reference):** search is a SQL function called through PostgREST (never build filter strings from user input); validate per type in TypeScript and canonicalize before storing; strict Zod bodies (no `origin`, ownership or ids from clients); list pages keep their state in the URL; audit every write. Provenance is enforced in the database for indicators (clients create only `local`, `protect_origin` blocks relabelling): give every new record table the same check, and write `external`/`demo` data only server-side. A page past the last one must be an empty page, not an error. Details and the recipe: `docs/API.md` and the Phase 4 handoff in `docs/ARCRADAR_PROGRESS.md`.
- **Permissions:** keys live in the database (migration `20260925100100`); `src/lib/rbac/permissions.ts` mirrors them and `tests/rbac.test.ts` fails on drift. Guards are a fast check; RLS is the authority, so repositories use the caller's client (`ctx.auth.supabase`), not the admin client.
- **Audit:** `writeAuditLog()` (service role, never throws) after an authorized action; add new action names to `src/lib/audit/actions.ts`. `audit_logs` is append-only.
- **Three Supabase clients, different trust levels:** `lib/supabase/client.ts` (browser, anon key), `server.ts` (acts as the signed-in user; RLS applies; default for data access), `admin.ts` (service role; bypasses RLS; server-only; only for audit-log writes, API key creation, admin user management, after authorization). `session.ts` + `src/proxy.ts` refresh auth cookies. Validate sessions with `auth.getUser()` for anything sensitive.
- **Authorization lives in the database.** Roles (admin / analyst / viewer), permission keys (`indicators:write`, ...) and `role_permissions` are reference data in migration `20260925100100`. RLS policies call `has_permission('<key>')`. App-side RBAC (Phase 2) must mirror those keys. Migration `20260925100500` holds all policies and column-level grants (clients cannot change `profiles.role_name`, read `api_keys.key_hash`, or write `audit_logs`).
- **Provenance:** every intel record has `origin` (`demo` | `local` | `external`). Never present demo or local data as live intelligence.
- **Provider abstraction:** UI → API → service → provider interface → Demo or external provider. External providers are enabled only when their server-side key is set; the app must work with none.
- **Telemetry (planned):** real events arrive from a Windows 10 endpoint via Wazuh Agent → Wazuh Manager → an ArcRadar ingest endpoint (Manager pushes over HTTPS with an API key). The nodes may sit on different computers and networks, so never hard-code hosts or assume one machine or subnet, and keep Wazuh-facing code behind a `TelemetrySource` adapter separate from enrichment providers. See `docs/TELEMETRY_ARCHITECTURE.md` before touching events, alerts, integrations or API keys.
- **Env:** `lib/env/public.ts` reads `process.env.NEXT_PUBLIC_*` literally (required for Next to inline them); `lib/env/server.ts` is `server-only`. Never import server env or the admin client from a Client Component.
- **Seed:** `supabase/seed.sql` is local-only demo data (including demo users) and uses `pg_temp` lookup helpers. It never runs on `supabase db push`.

## Phased workflow (important)

The project follows the phase plan in `docs/ARCRADAR_PROGRESS.md` (Phases 0–9).

- Read `docs/ARCRADAR_PROGRESS.md` first in every session.
- Execute **one phase only**, and only after the user explicitly says to continue with that phase (for example `CONTINUE PHASE 2`, or a clear "continue" in reply to your prompt asking for it). Never chain phases, and never treat "keep going" as permission to start the next one.
- A phase ends with: validation run, progress file updated, a concise report (completed, files changed, validation, limitations, next phase), then STOP.
- The full product spec is the user's original meta prompt, saved verbatim in `docs/ORIGINAL_PROMPT.md` (read it when a phase needs details not captured in the progress file). `docs/HANDOFF_PROMPT.md` is a ready-to-paste prompt for starting a fresh Claude Code session on this project.

## Constraints that shape every decision

- Production is Vercel + Supabase. No always-on server, no local filesystem persistence, no in-memory cross-request state, no background worker, no second database. nginx is local-only.
- Supabase service-role key and external provider keys are server-only. Never expose them to client code. Never commit secrets; keep `.env.example` current.
- Authorization must be enforced server-side and in RLS, not only in the UI.
- Do not deploy, and do not access the user's Vercel or Supabase accounts.

## Session log rule

At the end of every session (or after any meaningful chunk of work), append an entry to the **Session Log** below so future sessions can pick up where the last one left off. Each entry should include:

- Date (YYYY-MM-DD)
- What was done (files created/changed, decisions made)
- Open issues / next steps

Keep entries short. Newest entries go at the bottom.

## Session Log

### 2026-09-25

- Ran `/init`; the project folder was empty, with no files and no git repo.
- Created this CLAUDE.md with a session-log rule so each session gets recorded here.

### 2026-09-25 (session 2 — Phase 0 and prep)

- User supplied the ArcRadar meta prompt (phased plan, Vercel + Supabase target) and asked for nginx as a web server; delegated the open setup decisions to Claude.
- Phase 0: repo was empty; created `docs/ARCRADAR_PROGRESS.md`.
- Prep: installed Node.js LTS v24.19.0 and nginx 1.31.6 via winget. Decisions: nginx is a local-only reverse proxy; Supabase runs as a local stack (CLI + Docker) and the user creates a hosted project only at deploy time; OneDrive was not running.

### 2026-09-25 (session 2 — Phase 1, Foundation)

- User replied "davam ele" (continue) to the prompt asking for `CONTINUE PHASE 1`; ran Phase 1 only.
- Built: Next.js 16 app skeleton, env parsing, Supabase browser/server/admin/session clients, `src/proxy.ts`, API response envelope, `/api/health`, shared types; 6 migrations (32 tables, RLS with 111 policies, column grants, append-only audit log), demo seed with 3 demo users, SQL security tests, Vitest tests, nginx config + `scripts/nginx.ps1`, `.env.example`, `docs/LOCAL_DEVELOPMENT.md`, README stub.
- Validated: db reset from scratch, `npm run db:test` (8 groups pass), lint, typecheck, 12 Vitest tests, format check, production build, app + `/api/health` directly and through nginx, no service-role key in the client bundle.
- Gotchas hit: vitest 5 needs `@types/node` >= 22 (bumped to ^24); `LayoutProps` needs `next typegen` (added to `typecheck`); nginx needs `temp/` and `logs/` created up front; `$home` is reserved in PowerShell; `has_table_privilege` needs the schema taken from the row, since Postgres does not short-circuit AND.
- Local Supabase containers stopped at the end to free RAM (`npm run db:start` first next time). OneDrive was not running.
- Next: wait for the user's go-ahead for Phase 2 (backend foundation: Supabase Auth flows, sessions, RBAC in code, validation, error handling, audit writes). See the handoff notes in `docs/ARCRADAR_PROGRESS.md`.

### 2026-09-26 (session 3 — Phase 2, Backend foundation)

- User asked where we stopped, then replied "kec" (continue) to the prompt asking for `CONTINUE PHASE 2`; ran Phase 2 only.
- Built: API base (`publicRoute`/`protectedRoute` wrapper, `ApiError`, validation helpers, pagination, same-origin CSRF check, Supabase error mapping, JSON 404 catch-all), auth flows (login, logout, signup, forgot/update password, `/api/auth/me`, `/auth/callback`), RBAC mirror in `src/lib/rbac` with a migration drift test, audit foundation (`writeAuditLog`, metadata sanitizer, `GET /api/audit-logs`), `scripts/api-smoke.mjs` (`npm run api:smoke`), `docs/API.md`. Widened local redirect URLs in `supabase/config.toml` (needs a stack restart).
- Decisions: enumeration-safe auth responses, sign-up never signs the caller in, API JSON is snake_case, audit writes are best-effort, users-management endpoints deferred to Phase 7. No schema change.
- Validated: lint, typecheck, format, build, 89 Vitest tests, `db:test`, `api:smoke` 55/55 directly and through nginx, no secrets in the client bundle. Details in `docs/ARCRADAR_PROGRESS.md`.
- Next: wait for the user's go-ahead for Phase 3 (frontend foundation: design system, app shell, auth pages, page route protection). Local Supabase containers stopped at the end; OneDrive was not running.

### 2026-09-26 (session 3 — Wazuh telemetry requirement)

- User added a requirement forgotten in the original prompt: telemetry comes from a real Windows 10 machine (Wazuh Agent) through a Wazuh Manager into ArcRadar; the main computer only runs ArcRadar, the user's two other computers can host Windows 10 and the Manager, on any network layout. No placement decision wanted yet.
- Docs only, no code or phase work: added `docs/TELEMETRY_ARCHITECTURE.md`, decision 11 in `docs/ARCRADAR_PROGRESS.md`, and a Telemetry bullet in Architecture above. Checked against the Wazuh docs: the Manager is Linux-only, the agent connects to it on TCP 1514/1515, and the Manager's `<integration>` block can push alerts to a `hook_url` with an `api_key`.
- Open for later: where ingestion lands in the phase plan (it needs Phase 7 API keys), schema additions (`source_event_id`, `assets`, `telemetry` capability), and the questions listed in the doc. Phase 3 is still waiting for the user's go-ahead.

### 2026-09-26 (session 3 — Phase 3, Frontend foundation)

- User replied "davam ele" (continue) to the prompt asking for `CONTINUE PHASE 3`; ran Phase 3 only.
- Built: design tokens (dark default + light, server-rendered theme cookie, `npm run check:contrast`), UI primitives and states (`src/components/ui/`, dev-only gallery `/design`), app shell (sidebar, mobile drawer, header), sign-in / sign-up / forgot / reset pages, page guard (`getPageAuth`, `(app)` layout, screens for disabled and unavailable accounts), proxy redirect for cookie-less visitors, Overview page, nav config with `soon` items, error / loading / not-found / global-error states, session context (`useCan`, `<Can>`), Playwright E2E (`npm run e2e`, real Chrome, 32 tests) plus 137 Vitest tests. Added deps: `geist`, `lucide-react`, `@playwright/test`.
- Decisions: hand-written primitives instead of a component library; forms are thin clients of the JSON API; demo-account buttons only when `NEXT_PUBLIC_DEMO_LOGINS=true` (set by `db:env`), credentials from a server-only module; `forbidden()` not used (experimental), own `AccessDenied` component instead; no schema change.
- Gotchas hit: `error.tsx` gets `retry`, not `reset`; a bare try/catch around `cookies()` swallowed Next's prerender signal (use `unstable_rethrow`); Vitest 5 wants `vi.mock` at module top level (`vi.hoisted`); Playwright `getByLabel` also matches `aria-label`; a shell one-liner turned `\b` into a backspace character inside test files (scan for control characters after scripted edits).
- Validated: lint, typecheck, format, contrast, build, 137 unit tests, 32 E2E, `api:smoke` 55/55, `db:test`, screenshots reviewed in both themes and both sizes, no secrets or demo password in the client bundle. Details in `docs/ARCRADAR_PROGRESS.md`.
- Next: wait for the user's go-ahead for Phase 4 (indicators CRUD, search, filter, sort, pagination, global search). Servers stopped and local Supabase containers stopped at the end; OneDrive was not running.

### 2026-09-26 (session 3 — Phase 4, Core security data)

- User replied "CONTINUE PHASE 4"; ran Phase 4 only.
- Built: migration `20260926120000` (`escape_like`, `search_indicators`, `set_indicator_tags`, `protect_origin`, origin check on indicator inserts) with `supabase/tests/indicators.test.sql`; `src/lib/indicators/` (constants, per-type value validation, Zod schemas, repository, service, URL builder); API `/api/indicators`, `/api/indicators/[id]`, `/api/search`; pages `/indicators` (URL-driven search, filters, sorting, pagination), `/indicators/new`, `/indicators/[id]`, `/indicators/[id]/edit` with delete confirmation; header global search (combobox, `/` and Ctrl+K); UI primitives Select, Textarea, Pagination, ConfirmDialog, TagInput, ConfidenceMeter; `(app)/not-found`; audit actions `indicator.created|updated|deleted`. No new dependencies.
- Decisions: search as an invoker SQL function plus PostgREST for filters, sort and count; type and value fixed on edit; created records always `local` and the database enforces it; dates shown in UTC; tags shown neutral with the stored color only as a dot; no `/api/tags` (pages read tags on the server); relationships and actor/campaign links read-only for now.
- Gotchas hit: PostgREST answers 416 (`PGRST103`) for a page past the end (was a 500); a `hidden` utility can lose to `inline-flex` in a component's base classes (wrap instead); `overflow-wrap: break-word` does not shrink table cells, `anywhere` does; React's new lint rule rejects `setState` in effects (adjust state during render with a key); Playwright's caret hiding causes dev-only hydration warnings when screenshots land mid-hydration; `vi.mock` must be top-level; scripted multi-line replacements silently did nothing after Prettier reformatted a file (check that each edit landed); an apostrophe inside a `node -e '...'` one-liner breaks the shell quoting.
- Validated: lint, typecheck, format, contrast, build, 203 unit tests, DB tests (mutation-checked), `api:smoke` 105/105, E2E 57/57, screenshots reviewed, TypeScript-vs-database validation parity, no secrets in the client bundle. Details in `docs/ARCRADAR_PROGRESS.md`.
- Next: wait for the user's go-ahead for Phase 5 (intelligence modules: IP, domain, URL, hash lookups, vulnerabilities, provider layer). Servers and local Supabase stopped at the end; OneDrive was not running.
