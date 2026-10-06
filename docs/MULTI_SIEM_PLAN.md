# Multi-SIEM plan: Splunk first, pluggable for the rest

Status: **plan only, nothing built yet** (decision 32 in `ARCRADAR_PROGRESS.md`).

Goal: ArcRadar is not only a Wazuh companion. The same two abilities work for Splunk, and a third SIEM
(QRadar, Sentinel, Elastic) is a new small module, not a rewrite:

1. **Ingest**: alerts from the SIEM arrive in ArcRadar (triage, AI, cases, MITRE matrix, as today).
2. **Rules as code**: a person or the AI drafts a detection rule in the SIEM's own language, ArcRadar
   renders the file itself, an admin reviews it, it goes to GitHub, the SIEM side pulls it.

## Principles that do not change

- ArcRadar never connects to a SIEM host (Vercel has no route into a lab or company network, and it would
  be dangerous). Rules leave through GitHub; the SIEM pulls.
- The rule file is **always generated** from structured fields, never accepted from a person or the AI.
  That is what keeps dangerous commands out (Wazuh: no `active-response`; Splunk: no `| outputlookup`,
  `| sendalert`, `| script`, `| delete`, `| collect`, `| map`, `| rest`).
- Every value is escaped for the language it ends up in; every field and regex is validated first.
- Nothing executes. Provenance, audit, rate limits and RLS follow the existing recipe.

## Design (option A: one structured model per SIEM, shared table)

```
siem_rules
  id, siem ('wazuh' | 'splunk' | ...), rule_key (Wazuh id 100100+, Splunk app-unique name),
  name, level/severity, description, status (draft | pushed | rejected), source (manual | ai),
  spec jsonb          <- the SIEM-specific structured fields
  github_path, github_commit, pushed_at, ... (same lifecycle columns as wazuh_rules today)
```

A **dialect** is one module under `src/lib/siem-rules/dialects/<siem>.ts`:

```ts
interface RuleDialect<Spec> {
  siem: string;
  specSchema: ZodType<Spec>;          // strict, per-field checks (what xml.ts + schema.ts do today)
  render(rule): { path: string; content: string };  // the file committed to GitHub
  aiPrompt(): string;                 // teaches the model the spec shape, not the output language
}
```

Wazuh becomes the first dialect by **moving** `src/lib/wazuh-rules/{schema,xml,constants,prompt}.ts`
behind that interface; behavior and tests stay identical. Splunk is the second.

### Splunk spec (structured, no free SPL from anyone)

| Field | Meaning |
| --- | --- |
| `index`, `sourcetype` | where to search (validated names) |
| `conditions[]` | `field` + `contains` / `equals` / `regex` + value (same three ops as Wazuh) |
| `threshold` | optional: `count >= N` within a window, grouped `by` up to 3 fields |
| `window` / `schedule` | search time range and cron (bounded choices) |
| `severity`, `mitre_ids` | stored as the saved search's metadata |

`render()` builds one `savedsearches.conf` stanza from a fixed template (`search index=... | stats count
by ... | where count>=N`). Only the commands in that template can ever appear. Output file:
`splunk/arcradar_<key>.conf` (one per rule, like Wazuh's one XML per rule).

### Getting rules into Splunk

A small script on the Splunk host (the counterpart of `deploy/wazuh/apply-arcradar-rules.sh`) pulls the
repository, accepts only `arcradar_*.conf`, refuses any key or SPL command outside the allowed template,
validates with `splunk btool savedsearches list --debug`, copies into an app
`etc/apps/arcradar_rules/local/savedsearches.conf`, runs a debug refresh, and rolls back on refusal.
Cron every 10 minutes under `flock`, same as the Wazuh Manager.

### Getting alerts out of Splunk

Each generated saved search has a webhook alert action to `POST /api/ingest/splunk`. The Splunk-side
setup and the exact payload mapping live in `docs/SPLUNK_INTEGRATION.md` (to be written). On the ArcRadar
side this reuses the existing machinery: a `SplunkSource implements TelemetrySource`
(`src/lib/telemetry/splunk.ts`), `ingestRoute({ scope: "ingest:splunk" })`, a `splunk` integration row,
the API key scope, and `ingest_telemetry()` unchanged (it already takes normalized records and a
`source`).

## Steps (each one is shippable and tested on its own)

1. **Generalize, no behavior change.** Migration `siem_rules` + data copy from `wazuh_rules`; dialect
   interface; Wazuh dialect wraps the existing code; routes keep working (`/api/wazuh-rules` stays as an
   alias or is replaced by `/api/siem-rules?siem=wazuh`); all existing Wazuh unit, SQL and E2E tests stay
   green. This is the risky step, so it goes first and alone.
2. **Splunk dialect.** Spec schema, renderer, AI prompt, unit tests including injection attempts
   (`| outputlookup` inside a value, quotes, newlines, backticks, macros), DB tests, mutation checks.
3. **UI.** The Detection rules page gets a SIEM switch (Wazuh / Splunk); the form is spec-driven per SIEM;
   the preview shows the generated file.
4. **Splunk ingest.** Adapter, scope, integration row, `POST /api/ingest/splunk`, fictional sample
   (`ingest:sample` option), tests, smoke, API docs.
5. **Splunk lab.** Splunk Enterprise (free trial, 500 MB/day) in its own VMware VM, the apply script,
   the webhook alert action; end-to-end proof: draft in ArcRadar, push, Splunk loads it, an event fires
   it, the alert shows up in ArcRadar.
6. **Docs and deploy.** `SPLUNK_INTEGRATION.md`, README, DEMO_SCRIPT additions, migration pushed to the
   hosted project, then the code.

## Decisions made / open

- Decided: option A (structured model per SIEM), GitHub + script delivery (no REST write into Splunk).
- Open: Splunk Enterprise trial on a new Ubuntu VM (needs about 4 GB RAM, so the Windows 10 VM must be off
  or the Ubuntu Manager VM resized) versus Splunk Cloud trial (nothing local, but its saved searches can
  only be read through the REST API/ACS, so the pull-from-GitHub step would not apply).
- Not planned now: QRadar, Sentinel, Elastic dialects; Sigma import (it would sit on top of option A).
