# ArcRadar

An incident-response and threat-intelligence workspace for a small security team: indicators (IOCs),
IP/domain/URL/hash intelligence lookups, a vulnerability catalog, threat actors/campaigns/malware/MITRE
ATT&CK reference data, alerts with a real lifecycle and automatic deduplication, investigations (case
management), generated reports, and an AI layer that drafts analyses and checklists for a person to
review — never anything that acts on its own. Built as a Holberton portfolio project across twelve
phases; every decision behind it is in [`docs/ARCRADAR_PROGRESS.md`](docs/ARCRADAR_PROGRESS.md).

## What it does

- **Indicators.** Track IPs, domains, URLs and file hashes with a verdict, confidence, tags, and links to
  the threat actors, campaigns and malware that use them. Search, filter, sort and paginate; every record
  carries its provenance (`demo`, `local`, or `external`) so nobody mistakes a sample for a live finding.
- **Intelligence lookups.** Ask what is known about an IP, domain, URL or hash. Works out of the box on a
  built-in demo dataset; add a VirusTotal, AbuseIPDB or NVD key to ask real providers too — private and
  reserved addresses are never sent out, and nothing is ever fetched, uploaded or scanned.
- **Alerts and investigations.** Alerts follow a real lifecycle (new → acknowledged/investigating →
  resolved/false positive) with concurrency-safe status changes; a repeated alert links to its primary
  as a duplicate instead of opening a fresh row, and admin-curated detection rules can raise (never
  lower) an alert's severity. Investigations are the case file: notes, evidence references, a
  server-written history, and an AI-assisted checklist.
- **Threat intelligence.** Threat actors, campaigns, malware families and MITRE ATT&CK techniques,
  curated by administrators and linked to indicators, alerts and each other.
- **Telemetry.** A real endpoint pipeline: a Wazuh Manager pushes alerts over HTTPS with an API key
  (`docs/WAZUH_INTEGRATION.md`); ArcRadar never polls a sensor and never stores Wazuh credentials.
- **AI, governed not automated.** An alert, investigation or indicator page can ask a configured AI
  provider (Groq, OpenAI, Anthropic, DeepSeek, or a local Ollama) for a threat summary, an ATT&CK mapping,
  a severity check, a false-positive score, suggested response actions, an investigation checklist, or a
  verdict recommendation. Every answer is validated against a schema, stored immutably, labelled
  "AI-generated — analyst-assisted", and audited — it recommends and tracks, it never executes.
- **Reports, dashboard, admin.** Point-in-time report snapshots, a real dashboard (true counts, activity
  trends, top records), API-key management, per-provider integration switches, and a full audit log.

## Stack

Next.js 16 (App Router, `src/` layout) + TypeScript, Tailwind 4, Supabase (Postgres + Auth), Zod, Vitest,
Playwright. Production target: **Vercel + Supabase** — no always-on server, no local-filesystem
persistence, no in-memory cross-request state, no background worker (every "real-time-feeling" behavior,
including rate limiting and alert deduplication, runs inline on the request that needs it).

## Getting started

```bash
npm install
npm run db:start   # local Supabase in Docker; first run downloads a few GB
npm run db:reset   # applies supabase/migrations and the demo seed
npm run db:env     # writes the local Supabase URL/keys into .env.local
npm run dev         # http://localhost:3000
```

Full walkthrough, demo accounts, troubleshooting: [`docs/LOCAL_DEVELOPMENT.md`](docs/LOCAL_DEVELOPMENT.md).
Deploying your own copy to Vercel + Supabase: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Testing

```bash
npm run lint && npm run typecheck && npm run test   # ESLint, tsc, Vitest (700+ tests)
npm run db:test                                      # SQL security/constraint tests (stack running)
npm run api:smoke                                    # end-to-end API checks (app + stack running)
npm run e2e                                           # Playwright in real Chrome, incl. an axe pass
npm run check:contrast                                # WCAG contrast of the design tokens
```

Every phase of this project ended with all of the above green, directly and through a local nginx
reverse proxy — see the validation notes per phase in `docs/ARCRADAR_PROGRESS.md`.

## Architecture, in short

- **Layers:** Route Handler → auth/permission guard → Zod validation → service → repository (Supabase) or
  provider adapter. Three route wrappers (`publicRoute`, `protectedRoute`, `ingestRoute` for machines) do
  the same-origin check, session/permission guard, rate limiting and error mapping so a handler only
  writes its own logic. Recipe and every endpoint: [`docs/API.md`](docs/API.md).
- **Authorization lives in the database.** Roles, permission keys and RLS policies are the source of
  truth; the app-side RBAC mirror is checked against drift by its own test.
- **Provenance everywhere.** Every intelligence record carries `origin` (`demo`/`local`/`external`),
  enforced by the database, never presented as live intelligence when it is not.
- **Provider abstractions.** Intelligence lookups, telemetry ingestion and AI calls are each behind one
  interface with a demo/no-op default; every outbound call goes through exactly one, audited HTTP path
  per family (`getJson` for GET, `postJson` for POST), reviewed for SSRF (fixed HTTPS bases, no
  redirects, no admin-controlled hosts).
- **Security hardening:** a shared, database-backed rate limiter (no in-memory state to lose between
  serverless invocations); `httpOnly`/`secure` session cookies; a nonce-based Content-Security-Policy
  with no `unsafe-inline`; an automated accessibility pass (`@axe-core/playwright`) alongside the design
  system's own WCAG contrast checker.

The full picture — every phase's decisions, what was found and fixed along the way, and what is still
open — is `docs/ARCRADAR_PROGRESS.md`. Architecture deep dives: `docs/API.md` (API conventions and every
endpoint), `docs/TELEMETRY_ARCHITECTURE.md` and `docs/WAZUH_INTEGRATION.md` (the sensor pipeline),
`docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md` (the AI and response-orchestration layer).

## Security notes

Authorization is enforced in Row Level Security, not only in the app; API keys are stored as a hash
only and shown once; the audit log is append-only, even to the service role; secrets stay server-only
and are never in the client bundle (checked after every phase); demo and external data can never be
relabelled as `local`. See `docs/API.md`'s "Auth behavior worth knowing" and the security-hardening
bullet above for specifics, and report anything you find rather than exploit it — this is a portfolio
project, not a production security boundary anyone should rely on as-is.
