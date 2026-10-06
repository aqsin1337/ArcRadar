# Multi-SIEM plan: Splunk first, pluggable for the rest

Status: **steps 1-5 built (2026-10-06)**; step 6 (deploy) not started (decision 32 in `ARCRADAR_PROGRESS.md`).

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
  specSchema: ZodType<Spec>; // strict, per-field checks (what xml.ts + schema.ts do today)
  render(rule): { path: string; content: string }; // the file committed to GitHub
  aiPrompt(): string; // teaches the model the spec shape, not the output language
}
```

**Changed while building step 1 (2026-10-06):** Wazuh was NOT moved into `siem_rules`. Its rules live in
`wazuh_rules` with real columns, constraints and trigger statistics, are in production, and moving them
would put a working feature at risk for no gain. `siem_rules` (migration `20261006100000`) serves every
SIEM added from now on; the Detection rules page presents Wazuh and the others side by side, and the
Wazuh module can be folded in later if it ever matters. Rows are identified by a uuid and a per-SIEM
`rule_key`; the API is `/api/siem-rules/:siem/...`.

### Splunk spec (structured, no free SPL from anyone)

| Field                   | Meaning                                                                     |
| ----------------------- | --------------------------------------------------------------------------- |
| `index`, `sourcetype`   | where to search (validated names)                                           |
| `conditions[]`          | `field` + `contains` / `equals` / `regex` + value (same three ops as Wazuh) |
| `threshold`             | optional: `count >= N` within a window, grouped `by` up to 3 fields         |
| `window` / `schedule`   | search time range and cron (bounded choices)                                |
| `severity`, `mitre_ids` | stored as the saved search's metadata                                       |

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

1. **Generic engine (done).** `siem_rules` table, the `RuleDialect` interface and registry, the shared
   lifecycle (create, AI draft, edit, reject, push, delete, audit, rate limits), routes under
   `/api/siem-rules/:siem`. Wazuh is untouched, so none of its tests could change.
2. **Splunk dialect (done, with step 1).** Fixed-template renderer, spec schema,
   `assertSafeSplunkConf` (only `search`, `regex`, `stats`, `where` can appear), AI prompt, unit tests
   including injection attempts, DB tests with mutation checks, smoke checks. NOT yet verified against a
   real Splunk: the escaping of backslashes inside the `regex` command is checked in step 5.
3. **UI (done).** The Detection rules page has a "Splunk rules" tab next to "Wazuh rules" and "Severity rules":
   `SiemRulesManager` (the shared workflow: manual form, AI draft, edit, reject, push, delete, a per-SIEM
   `SIEM_UI` entry for the form, the badges and the file label) and `SplunkRuleForm` (index, sourcetype,
   schedule, conditions, "only when it repeats" with count, window and group-by). The preview shows the
   generated `savedsearches.conf` stanza. A new SIEM adds one form component and one `SIEM_UI` entry.
4. **Splunk ingest (done).** `POST /api/ingest/splunk`, scope `ingest:splunk`, `SplunkSource` adapter
   (`src/lib/telemetry/splunk.ts`), migration `20261006110000` (the `splunk` integration row and `ingest_telemetry()`
   accepting that source; the function body is otherwise the Phase 6b one), sample file and
   `npm run ingest:sample -- --siem splunk`, unit tests, a SQL test with a mutation check, smoke checks. Rendered
   Splunk files now carry `action.arcradar_forward.param.name` so the alert gets the rule's name as its title.
   The Splunk-side custom alert action that builds these requests is step 5.
5. **Splunk lab (done).** Splunk Enterprise 10.0.2 on its own Ubuntu VM (192.168.218.30), the app and the alert
   action in `deploy/splunk/`, the apply script, end-to-end proof; see [SPLUNK_INTEGRATION.md](SPLUNK_INTEGRATION.md)
   ("Verified on the lab"). It found one real bug: a saved search must not start with `search` (fixed, and the
   safety check now whitelists the exact shape of every segment). Not yet done: the real GitHub hop (a local Git
   repository stood in) and a Universal Forwarder on the Windows VM as the event source.
6. **Docs and deploy.** `SPLUNK_INTEGRATION.md`, README, DEMO_SCRIPT additions, migration pushed to the
   hosted project, then the code.

## Decisions made / open

- Decided: option A (structured model per SIEM), GitHub + script delivery (no REST write into Splunk).
- Open: Splunk Enterprise trial on a new Ubuntu VM (needs about 4 GB RAM, so the Windows 10 VM must be off
  or the Ubuntu Manager VM resized) versus Splunk Cloud trial (nothing local, but its saved searches can
  only be read through the REST API/ACS, so the pull-from-GitHub step would not apply).
- Not planned now: QRadar, Sentinel, Elastic dialects; Sigma import (it would sit on top of option A).
