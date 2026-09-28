# AI and response orchestration: architecture

Status: **Phases 8, 9 and 10 all built (2026-09-27 and 2026-09-28, decisions 22, 23 and 24 in
`docs/ARCRADAR_PROGRESS.md`). This plan is fully implemented.** This is the requirement and the design it
implied, in the same spirit as `docs/TELEMETRY_ARCHITECTURE.md`: written so a fresh session can pick it up.
Everything below describes the plan as agreed; where a phase actually built something slightly differently, or
narrower, a note says so inline and decisions 22/23/24 have the full account. Phase 11 (security/quality/
responsiveness hardening, renumbered by this plan's insertion) still needs its own explicit go-ahead per the
phased workflow in `CLAUDE.md`.

## Requirement (as given by the user, 2026-09-27)

ArcRadar is repositioned from "a threat-intelligence workspace" to:

> An incident response, alert triage, investigation, case management, and response orchestration
> platform. ArcRadar complements existing SIEM platforms by centralizing triage, enrichment,
> investigation, cases, analyst workflows, and governed response actions.

AI is added as a cross-cutting capability:

> AI provides analyst-assisted summaries, risk assessments, investigation recommendations, response
> guidance, and evidence-based verdict recommendations.

Concretely, in the user's words:

- Run **Groq** now. The AI provider must be **admin-configurable**: OpenAI, Anthropic Claude, DeepSeek and
  Ollama (or another local model) should be selectable later, without a code change.
- AI should generate, where feasible: **threat summaries**, **attack vector analysis (MITRE ATT&CK)**,
  **severity validation**, **immediate response actions**, an **investigation checklist**, and **false
  positive scoring**.
- Key features to add: **AI-powered alert analysis**, **false positive likelihood scoring**,
  **investigation checklist generation**, **incident response recommendations**, an **alert deduplication
  engine**, and **custom rule prioritization (rule ids 100000-999999)**.
- Continue from where the project is (Phase 7 done); this is additive, not a rewrite. The user may ask for
  some of this to be cut or simplified later — flagged below wherever I am proposing a narrower first cut
  than the literal ask, with the reason.

**This revises decision 18 of the original meta-prompt** ("do not attempt to build an enterprise-scale
SIEM/SOAR replacement"). The scope stays deliberately narrow to stay inside that spirit: ArcRadar
**recommends and tracks** response actions a human approves; it never executes anything against a real
system on its own (matches the existing rule that "nothing is ever fetched, uploaded or scanned" for intel
providers, and the constraint against "dangerous functionality that enables arbitrary exploitation").

## What "case management" already is

ArcRadar already has **Investigations** (Phase 6): a status workflow (open → investigating → contained →
resolved/closed), an assigned analyst, linked indicators and alerts, notes, evidence, and a timeline built
from all of that. That _is_ case management. Rather than add a parallel "Case" entity (a purely cosmetic
duplicate that would fork two record types doing the same job), **investigations keep their name and
schema**, and the product language calls them "cases" where that reads more naturally. If the user wants a
real rename (`investigations` → `cases` in the schema, routes and UI), that is a mechanical but wide-reaching
change touching most of Phase 6 and 6b; flagging it here as an option, not doing it silently.

## AI provider abstraction

A third provider family, next to `IntelProvider` (outbound enrichment lookups) and `TelemetrySource` (inbound
sensor events): `AiProvider` (outbound calls to a language model). Same shared vocabulary and rules as the
existing two: a provider is used only when configured, nothing is ever sent that the workspace itself
couldn't already show the caller, and every call is audited.

```
src/lib/ai/
  types.ts       AiProvider interface, AiRequest/AiResponse, the analysis kinds
  http.ts        the only outbound path for AI calls (POST, unlike intel's getJson which is GET-only)
  registry.ts    which providers are configured (env key present), which one is active (DB setting)
  service.ts     one function per feature (summarizeAlert, mapAttackVectors, ...): builds the prompt from
                 data the caller can already read, calls the active provider, validates the JSON answer
                 against a zod schema, stores it, audits it
  prompts.ts     the prompt templates, one per analysis kind, versioned (a prompt change should be visible
                 in the stored analysis, so re-runs are comparable)
  providers/
    groq.ts        the default, working adapter (OpenAI-compatible chat completion API)
    openai.ts
    anthropic.ts
    deepseek.ts
    ollama.ts      local; see "Ollama and SSRF" below
```

### `AiProvider` interface (sketch)

```ts
type AiProvider = {
  info: { id: "groq" | "openai" | "anthropic" | "deepseek" | "ollama"; name: string };
  /** One chat completion call. `schema` describes the JSON shape the caller needs back (the adapter asks
   * the model for JSON and the service still validates the answer against `schema` before trusting it). */
  complete(request: {
    system: string;
    user: string;
    schema: z.ZodType;
    maxOutputTokens: number;
  }): Promise<{ data: unknown; model: string; usage?: { input: number; output: number } }>;
};
```

Every adapter is asked for **structured JSON**, not prose, so a stored analysis is always a typed record, not
a blob of text the UI has to parse loosely (matches the demo/live intel results: a card renders a known
shape, never raw provider text).

### Where the outbound HTTP path lives

`src/lib/intel/http.ts`'s `getJson` is GET-only and was built for lookups. AI calls are POST with a JSON
body. A new `src/lib/ai/http.ts` mirrors every one of `getJson`'s rules for the POST case: a fixed HTTPS base
per provider (never built from admin input), no redirects, a deadline, a response-size cap, the API key in a
header (never the URL or the body), and errors that carry no body or key. This is the same non-negotiable
architecture rule as decision 14, extended to a second HTTP verb.

### Choosing the active provider

`integrations` (the existing provider catalog, Phase 1/6b/7) gains rows for `groq`, `openai`, `anthropic`,
`deepseek`, `ollama` with `capabilities = ['ai']` (the capability check constraint needs `'ai'` added). Each
row's `configured` status already means "the app can use this" (a server-side key is set — decision 5); a
new one-row settings table, `ai_settings (active_provider text references integrations(provider), active_model
text, updated_by, updated_at)`, holds **which one is currently selected**, since "configured" and "the one
in use right now" are different questions (an admin might have both Groq and OpenAI keys set but want only
one active). `GET/PATCH /api/ai/settings` (admin, a new permission `ai:manage`) lists the configured
providers and lets an admin switch the active one and its model name; the Integrations page gains an "AI
provider" section next to the existing enable/disable switches.

### Ollama and SSRF

Every other provider has a fixed, hardcoded HTTPS base (`https://api.groq.com`, ...), which is what keeps the
outbound path safe from SSRF (decision 14: "no user input in the request's URL, ever"). A local Ollama server
is reached by a **host the admin controls**, which is exactly the shape of request the rest of this codebase
refuses to make from user input. The safe middle ground: `OLLAMA_BASE_URL` is a **server environment
variable**, set by whoever deploys ArcRadar, never editable from the admin UI. This keeps the same safety
property (the URL is fixed at deploy time, not attacker- or even admin-session-reachable) while still letting
a self-hosted deployment point at its own model server. If the user wants admin-UI-configurable hosts instead,
that is a deliberate SSRF-relevant trade-off to decide explicitly, not a default.

### New environment variables (server-only, `.env.example`)

`GROQ_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY` (all optional; the app works with
only Groq's set, or none — no AI feature then appears, same honesty rule as the intel providers),
`OLLAMA_BASE_URL` (optional, local-network use).

## AI features and where they attach

Every AI answer is stored in one new table, so a feature is "generate a `kind` of analysis for this
alert/investigation/indicator" rather than six unrelated tables:

```sql
create table ai_analyses (
  id uuid primary key default gen_random_uuid(),
  kind text not null,                    -- 'threat_summary' | 'attack_vector' | 'severity_validation'
                                          -- | 'response_actions' | 'investigation_checklist'
                                          -- | 'false_positive_score' | 'verdict_recommendation'
  subject_type text not null,            -- 'alert' | 'investigation' | 'indicator'
  subject_id uuid not null,
  provider text not null,
  model text not null,
  prompt_version int not null,
  content jsonb not null,                -- the validated, typed answer (shape depends on `kind`)
  requested_by uuid references profiles(id),
  created_at timestamptz not null default now()
);
```

A request is never automatic: an analyst clicks "Ask AI" (or a specific action, "Summarize", "Check for
false positive", ...) on an alert/investigation/indicator page; the answer renders in a clearly labeled card
("AI-generated — analyst-assisted, not a verdict") next to, never instead of, the record's real fields.
Re-running creates a new row (like reports: an immutable answer at that moment, not something that silently
changes under the analyst); the UI shows the latest per kind and a small history.

| Feature (user's words)                | `kind`                    | Attaches to   | Shape (draft)                                                                                                                        |
| ------------------------------------- | ------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Threat summary                        | `threat_summary`          | alert         | `{ summary: string, key_points: string[] }`                                                                                          |
| Attack vector analysis                | `attack_vector`           | alert         | `{ techniques: [{ id, name, confidence }], narrative: string }`                                                                      |
| Severity validation                   | `severity_validation`     | alert         | `{ agrees: boolean, suggested_severity, reasoning: string }`                                                                         |
| Immediate response actions            | `response_actions`        | alert         | `{ actions: [{ title, why, urgency }] }` (feeds the response catalog below)                                                          |
| Investigation checklist               | `investigation_checklist` | investigation | `{ items: string[] }`                                                                                                                |
| False positive scoring                | `false_positive_score`    | alert         | `{ score: 0-100, reasoning: string }`; cached on `alerts.ai_fp_score` for the list/sort                                              |
| Evidence-based verdict recommendation | `verdict_recommendation`  | indicator     | `{ verdict, confidence, reasoning: string }` — a recommendation only; applying it is a normal, audited indicator edit by the analyst |

`alerts.ai_fp_score numeric` (nullable) is a cache of the latest `false_positive_score` analysis, so the alert
list can show and sort by it without joining `ai_analyses` on every row (the same reasoning as
`integrations.last_sync_at`).

## Response orchestration (governed, not automated)

"Governed response actions" means: recommend, track, never execute.

```sql
create table response_actions (             -- the catalog, curated like threat intelligence
  id uuid primary key default gen_random_uuid(),
  title text not null, description text, category text,   -- e.g. 'containment', 'eradication', 'communication'
  origin data_origin not null default 'local',
  created_by uuid references profiles(id), created_at timestamptz not null default now()
);
create table response_action_log (          -- one row per recommendation/execution on a specific alert or case
  id uuid primary key default gen_random_uuid(),
  action_id uuid references response_actions(id),
  alert_id uuid references alerts(id), investigation_id uuid references investigations(id),
  status text not null,                     -- 'recommended' | 'acknowledged' | 'completed' | 'skipped'
  source text not null,                     -- 'ai' | 'analyst'
  notes text, performed_by uuid references profiles(id), performed_at timestamptz,
  created_at timestamptz not null default now()
);
```

An AI `response_actions` analysis (the table above) can seed rows here as `status = 'recommended'`; an
analyst marks each one acknowledged, completed or skipped, with an optional note — an auditable response
trail per alert or case, with no code path that ever reaches out and does the action itself.

## Alert deduplication engine

Not AI: a deterministic fingerprint, computed the same way telemetry ingestion already computes
`source_event_id`. `alerts.fingerprint text` (hash of the normalized `rule id / source / asset / a stable
piece of the payload`, bucketed to a time window, e.g. 15 or 60 minutes) and `alerts.duplicate_of uuid
references alerts(id)`. On ingest (extending `ingest_telemetry()`) and on manual creation, a new alert whose
fingerprint matches an existing, still-open alert within the window is linked as a duplicate instead of
opening a fresh one in the "New" queue; its occurrence still counts (`alerts.duplicate_count int`) so nothing
is silently lost, and the primary alert's page lists its duplicates. Exact grouping key needs a decision once
this is scheduled (see "Open questions").

## Custom rule prioritization

A `detection_rules` table so an admin/analyst can define ArcRadar-side rules that run **inline, at ingest
time** (there is no background worker to run them later — the constraint from decision 1 still holds):

```sql
create table detection_rules (
  id integer primary key check (id between 100000 and 999999),  -- mirrors Wazuh's own custom-rule id space,
                                                                  -- chosen so the two number ranges never collide
  name text not null, description text,
  conditions jsonb not null,     -- match criteria against an incoming record's fields
  severity severity,             -- override/assert a severity when the rule matches
  priority integer not null,     -- evaluation order and tie-break for conflicting rules
  enabled boolean not null default true,
  origin data_origin not null default 'local',
  created_by uuid references profiles(id), created_at timestamptz not null default now()
);
```

Evaluated as one more step inside the ingest route (and the manual alert-creation path), in priority order,
against the normalized record before it is stored: a match can raise the severity, add a tag, or force an
alert even below the Wazuh level-7 threshold. `conditions`' exact grammar (a small DSL vs. a fixed set of
field/operator/value rows) is an open question — a fixed set is safer and easier to validate; a DSL is more
flexible but reopens the "never build a filter from free text" concern this codebase has avoided everywhere
else.

## Permissions

New keys (added to the migration `20260925100100` mirror, `src/lib/rbac/permissions.ts`): `ai:use` (ask for
an analysis; analysts and admins) and `ai:manage` (choose the active provider/model; admins). Response
actions and detection rules reuse the existing `investigations:write`/`alerts:write` and a new
`rules:manage` (admin) the same way indicators reused their own table's permissions.

## Proposed phases

| #          | Phase                                              | Covers                                                                                                                                                                                                                                                             | Status   |
| ---------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- |
| 8          | AI integration foundation                          | `src/lib/ai/`, the five adapters (Groq first and default), `ai_settings`, the Integrations page's new AI section, `ai_analyses`, and the alert-page features: threat summary, attack vector, severity validation, false positive score, immediate response actions | **Done** |
| 9          | Investigations checklists & response orchestration | `investigation_checklist_items`, the AI checklist button, `response_actions` + `response_action_log`, evidence-based verdict recommendations on the indicator page                                                                                                 | **Done** |
| 10         | Alert deduplication & custom detection rules       | fingerprinting and grouping (ingest + manual), `detection_rules`, inline evaluation at ingest, a Rules management page                                                                                                                                             | **Done** |
| 11 (was 8) | Security / quality / responsiveness hardening      | as before, plus rate-limiting the new AI endpoints (a real cost and abuse surface) and an SSRF review of the new POST outbound path                                                                                                                                | Pending  |
| 12 (was 9) | Docs / final QA / deployment readiness             | as before                                                                                                                                                                                                                                                          | Pending  |

Phase 11 still needs its own explicit go-ahead.

## What Phase 8 actually built (2026-09-27)

Matches this plan closely; the differences, all narrowings flagged for the user to override, are:

- `active_model` is a free-text field on `ai_settings`, not a per-provider dropdown of known models — model
  catalogs change often and vary per provider, so a fixed list would go stale fast. A typo only surfaces when
  the provider itself rejects the request (a plain `503`).
- `ai_analyses.kind` and `.subject_type` are check-constrained to exactly what Phase 8 writes (the five
  alert-page kinds, `subject_type = 'alert'` only), not the full set the table will eventually hold. Phase 9
  widens both with a **new** migration, never by editing `20260927130000` — the same discipline every earlier
  phase has followed for its own schema.
- `response_actions` (the "immediate response actions" kind) is stored and shown as a read-only analysis card
  in Phase 8. Turning its `actions[]` into individually tracked `response_action_log` rows (recommended →
  acknowledged/completed/skipped) is still Phase 9's job, exactly as planned above — Phase 8 does not seed
  anything into a catalog that does not exist yet.
- Not verified with any real provider key (none exist on this machine): every adapter's request-building and
  response-parsing is unit-tested against fixtures written from each provider's own API documentation, the
  same caveat Phase 5's live intel providers carried before a real key existed. Ollama additionally has no
  test against a real local server — none exists in this lab.
- Everything else — the `AiProvider` interface, `postJson`'s SSRF rules and its one `allowInsecure` exception
  for Ollama, the `integrations` + `ai_settings` provider-selection split, `ai_analyses`'s shape and
  provenance-free design, the permission split (`ai:use` vs `ai:manage`), and "recommend and track, never
  execute" — was built exactly as designed above. Full account: decision 22 in `docs/ARCRADAR_PROGRESS.md`.

## What Phase 9 actually built (2026-09-28)

Matches this plan closely; the differences, all narrowings flagged for the user to override, are:

- `response_action_log` is wired up for **alerts only**. The column and its RLS policies already accept an
  `investigation_id` instead of an `alert_id` (the schema above always had both), but no service function or
  page reads or writes that side yet — a case-scoped response-action list is a small, mechanical follow-up
  whenever it is wanted (Phase 10's handoff notes in `docs/ARCRADAR_PROGRESS.md` have the detail).
- An AI `response_actions` analysis always **creates a new catalog entry** per suggested action; there is no
  fuzzy match against an existing `response_actions.title`. Two AI runs that both suggest "Isolate the host"
  produce two catalog rows. An administrator can merge or delete duplicates by hand on `/response-actions`;
  automatic de-duplication of AI suggestions was judged not worth the false-merge risk for a first cut.
  (Unrelated to the alert-deduplication **engine** in this same doc, which is Phase 10's own, different,
  deterministic-fingerprint feature.)
- The checklist and verdict-recommendation panels show only the **latest** state (the current checklist list;
  the most recent `verdict_recommendation` analysis), not a browsable history of past AI runs, even though
  every past `ai_analyses` row is kept in the database exactly as Phase 8 designed. A history view is a UI-only
  follow-up whenever it is wanted.
- No new permission keys were needed — `investigation_checklist_items` and `response_actions`/
  `response_action_log` all reuse the existing `investigations:write`/`alerts:write`/`investigations:read`/
  `alerts:read`, exactly as this doc proposed. `rules:manage` (Phase 10) is still unused.
- The `ai_analyses` table's `kind` and `subject_type` check constraints, and its RLS policies, were widened by
  a **new** migration (`20260927140000`) rather than by editing Phase 8's `20260927130000`, per the project's
  own "never edit an applied migration" rule — plus a new constraint neither phase's plan spelled out in SQL
  until now: `ai_analyses_kind_subject_match_check`, pairing each `kind` to exactly the one `subject_type` the
  table above's own list already implied (an alert-only kind can no longer be stored against an investigation
  or an indicator, and vice versa). Caught one otherwise-possible bug class this widening introduced.
- Everything else — the checklist and verdict-recommendation features' shapes, the response-action workflow
  (`recommended → acknowledged/completed/skipped`, no backwards move once `completed`/`skipped`), and
  `response_actions`'s catalog being provenance-protected like other curated reference data — was built exactly
  as designed above. Full account: decision 23 in `docs/ARCRADAR_PROGRESS.md`.

## What Phase 10 actually built (2026-09-28)

Matches this plan closely; the differences, all narrowings flagged for the user to override, are:

- Both features turned out to fit in **one** `before insert` trigger on `alerts` rather than separate
  application-level checks: `alerts_dedup_and_rules()` evaluates enabled rules in priority order (raising
  severity, never lowering it, and setting `matched_rule_id`) and then computes the fingerprint and links a
  duplicate, all inline, all in the database. This means `ingest_telemetry()` and a manual `POST /api/alerts`
  share the exact behavior for free — no separate "evaluate rules" call was ever added to either code path.
- The deduplication window is a **fixed 60 minutes**, and the fingerprint is a fixed, small set of fields
  (`source`, a normalized `title`, `asset_id`, `indicator_id`) — not admin-configurable, and not inspecting
  arbitrary payload contents. This answers the "deduplication window and exact fingerprint fields" open
  question below, but as a fixed default rather than a setting; revisit if a real deployment's alert volume
  shows the window is wrong.
- `detection_rules.conditions` is the **fixed field/operator/value grammar** this doc leaned toward, not a
  more expressive DSL: exactly 6 `(field, op)` pairs exist at all (`title`/`description` `contains`,
  `source` `eq`/`contains`, `severity` `eq`, `technique_id` `eq`), and the database's own
  `detection_rule_matches()` fails closed on anything else, even a condition inserted directly (bypassing
  the API's own Zod validation) — defense in depth beyond the usual "the app validates it" story.
- A rule can only **raise** severity and trace itself (`matched_rule_id`) on the matching alert. It cannot
  add a tag, and it cannot force an alert to exist below Wazuh's own level-7 threshold — that threshold
  decision still lives entirely in the telemetry adapter/Manager configuration, untouched this phase.
- No "un-link a duplicate" admin action, and no retroactive re-evaluation of existing alerts when a rule is
  added or edited — a rule only ever affects alerts created from that point on.
- The alert **list table** carries no duplicate/rule badges; only a `duplicates` filter (default hidden,
  `?duplicates=show` reveals them) and the alert detail page (a "Matched rule" row, a "Duplicates" card on a
  primary, a "this is a duplicate of…" notice on a duplicate) surface any of this.
- **A real bug found only by an E2E test reading the rendered page, not by a unit test or the smoke test**:
  a self-referential PostgREST embed (`alerts!duplicate_of`, meant as "the one alert I duplicate") resolved
  in the _reverse_ direction instead ("the alerts that duplicate me") — Postgres/PostgREST cannot tell a
  self-join's two directions apart from the column hint alone. `AlertDetail.primary_alert` came back empty
  on a genuine duplicate even though the database had linked it correctly. Fixed by replacing the embed with
  an explicit one-row query, the same pattern the (correctly-working) `duplicates` list already used.
- Everything else — the trigger's rule-then-dedup ordering, `rules:manage` as a genuinely new admin-only
  permission, the `/detection-rules` catalog page, and excluding a duplicate from every alert count
  (`alert_status_counts`, `alert_severity_counts`, `activity_series`, the dashboard's own two head-counts) —
  was built exactly as designed above. Full account: decision 24 in `docs/ARCRADAR_PROGRESS.md`.

## Open questions (the user's call)

- ~~Exact prompts and how much workspace context to include~~ — **answered by Phase 8**: `src/lib/ai/prompts.ts`
  sends only what the alert page itself already shows the caller (title, description, severity, status,
  source, origin, indicator, asset, tagged techniques, source event), never anything fetched specially for
  the AI feature; Phase 9's investigation and indicator prompts follow the identical rule (checklist context
  is the investigation's own status/notes/linked items; the verdict-recommendation context is the indicator's
  own type/value/confidence/related records) — revisit only if a later kind needs more.
- ~~The deduplication window and the exact fingerprint fields~~ — **answered by Phase 10**: a fixed 60
  minutes and a fixed (source, title, asset, indicator) key; see "What Phase 10 actually built" above. Open
  only in the sense that neither is admin-configurable yet.
- ~~`detection_rules.conditions`: a fixed field/operator/value grammar, or something more expressive~~ —
  **answered by Phase 10**: the fixed grammar, exactly 6 (field, op) pairs, fails closed on anything else.
- Whether "Investigations" should actually be renamed to "Cases" in the schema/UI, or stay as-is with the
  product description using "cases" informally (current proposal: stay as-is; Phase 9's checklist feature
  reinforces that investigations already behave like cases without a rename).
- Cost/rate control per AI provider (a portfolio project on free tiers can exhaust a quota fast); whether to
  cap requests per analyst per day even before Phase 11's general rate limiting. **Still open** — Phase 9
  added two more AI-calling endpoints (investigation checklist, indicator verdict) on top of Phase 8's five,
  with no new cost control beyond the existing `ai:use` role gate and small per-kind output-token budgets
  (`AI_MAX_OUTPUT_TOKENS`); worth deciding before or during Phase 11.
- Whether response actions should ever extend to investigations, not just alerts (Phase 9 narrowed to alerts
  only — see "What Phase 9 actually built" above). **Still open.**
- Whether the dedup window or fingerprint fields should become admin-configurable, and whether a rule should
  ever re-evaluate existing alerts rather than only new ones (Phase 10 narrowed both away — see "What
  Phase 10 actually built" above). **Still open.**
- ~~Whether Ollama needs to be reachable at all for this lab~~ — **built anyway in Phase 8**, stubbed and
  documented as untested (no local model server exists in this lab), the same way the live intel providers
  were before a real key existed; its adapter and `OLLAMA_BASE_URL`'s `allowInsecure` handling are unit-tested,
  just never against a real server.
