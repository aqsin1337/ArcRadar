# Splunk rule sync: real fields, imported rules, AI enhancement

Status: **phase A done (2026-10-06): A1 (field catalog) deployed to production; A2 (backtest and test mode) built and verified on the lab Splunk; B, C, D not started.** Follows [MULTI_SIEM_PLAN.md](MULTI_SIEM_PLAN.md) and
[SPLUNK_INTEGRATION.md](SPLUNK_INTEGRATION.md). The request came from using the finished Splunk integration:
writing a rule in ArcRadar felt like guessing (field names typed by hand, no way to know before pushing whether the
rule finds anything), and an analyst who writes alerts in Splunk itself had no way to bring them into ArcRadar.

## What ArcRadar should be, for rules

1. **From scratch (stays):** a person or the AI drafts a rule in ArcRadar. New: it picks **real fields and real
   values** from what Splunk actually holds, and sees a **backtest** before pushing.
2. **From Splunk (new):** an analyst writes an alert in Splunk, without ArcRadar. The Splunk host reports it to
   ArcRadar; ArcRadar shows it, and the AI can **explain it, add the missing severity, MITRE ids, name and
   description, review it for false positives and weaknesses**. Approved metadata goes back to Splunk and turns on
   "Send to ArcRadar", so when it fires the alert arrives in ArcRadar already complete.

Both directions keep the principle that ArcRadar never connects to Splunk: the Splunk host calls ArcRadar.

## The one hard part: letting the AI change the SPL itself

Metadata (name, severity, MITRE, description, "forward to ArcRadar") is safe to change automatically after a
person approves it. **Rewriting an analyst's SPL is not**: arbitrary SPL can write files or lookups
(`| outputlookup`), send things (`| sendalert`), run scripts or delete data. ArcRadar's current rules avoid this
with a closed grammar, which is also why they are simple. So:

- Imported rules are shown with their **raw SPL, read-only**. The AI may explain it and propose an improved search
  as **text for the analyst to copy into Splunk**; ArcRadar does not deploy it.
- Phase D (last, optional) allows deploying edited SPL, only with a real SPL validator (a command allowlist of
  read-only commands, checked recursively inside subsearches, fail closed on anything unparsed, enforced twice: in
  ArcRadar and again on the Splunk host), a mandatory backtest and a human approval. Until that exists, nothing
  executes SPL ArcRadar did not generate from a closed template.

## Phases (each one shippable; each needs its own go-ahead)

### A. Field catalog and backtest

- **Splunk side:** a small sync script on the Splunk host (cron, next to the apply script) that, using the Splunk
  REST API on localhost, collects per index and sourcetype the **field names, how often each appears and a few
  example values** (`| fieldsummary` over the last 24 h, bounded), and POSTs it to ArcRadar with the existing
  `ingest:splunk` key. It needs a Splunk login: a **dedicated, minimal role/user** (search on the allowed
  indexes, read saved searches) instead of `admin`.
- **ArcRadar:** a service-only SQL function and a table for the catalog (written only server-side, `external`
  provenance, like telemetry), `POST /api/ingest/splunk/catalog`, `GET /api/siem-rules/splunk/fields`.
- **Rule form:** index and sourcetype become pickers of what exists; a condition's field is a picker with counts
  and example values (free text still possible, with a warning when the field is not in the catalog); the AI prompt
  receives the catalog so it only uses fields that exist.
- **Backtest:** when the sync script sees a rule file (draft pushed in "test" form, or any `arcradar_*` rule), it runs
  the search over the last 24 h / 7 d through REST and reports "would have fired N times, groups ..." to ArcRadar,
  shown on the rule card. A rule can be pushed in **test mode** (the saved search runs but the action is off), so
  the result exists before anything alerts.

### B. Imported rules

- The sync script lists the saved searches that are **not** ArcRadar's (alerts and scheduled searches in any app),
  with SPL, schedule, time range, severity, actions and a hash, and reports them (`POST .../rules`), on a schedule and
  only when changed.
- ArcRadar stores them as `source = 'imported'` rows (service-side write, `external` provenance), keyed by Splunk
  app and name (new column; the current `rule_key` pattern cannot hold names with spaces). Splunk's own version is the
  truth: a re-sync updates the imported copy and marks any local enhancement as "outdated" if the SPL changed.
- UI: an "Imported from Splunk" view on the Splunk rules tab: raw SPL, schedule, "forwards to ArcRadar: yes/no",
  last fired, backtest.

### C. AI on imported rules, metadata overlay

- AI analyses (same pattern as alert analyses: validated schema, stored immutably, audited): **explain the rule**,
  **suggest severity, MITRE ids, a clear name and description**, **false-positive risks and weaknesses**, **a
  suggested improved SPL as text**.
- A person approves the metadata. It is delivered like a rule is today (GitHub file `splunk/overlays/<id>.json`,
  committed by the app, pulled by the apply script) and applied on the Splunk host **through REST, and only these
  keys**: `action.arcradar_forward` (on), its `param.name`, `param.severity`, `param.mitre`, `alert.severity`,
  `description`. The search itself is never touched. The apply script refuses any other key, and records what it
  changed so it can be undone.
- Result: the analyst's own alert, unchanged in Splunk, now reaches ArcRadar with the AI-completed severity and MITRE.

### D. Editing SPL (optional, last)

Only after A (backtest) and a validator as described above. Possibly a "replace" flow that creates the ArcRadar
version and disables the original. Not committed to; decide after C is in use.

## Also needed along the way

- Provenance and audit for everything the sync writes; rate limits on the new endpoints; RLS like the other rule
  tables; SQL, unit and smoke tests with the usual mutation checks; real verification on the lab Splunk each phase.
- The sync script is part of `deploy/splunk/` and is installed and verified over SSH like the apply script.
- Known smaller items to fold in: a threshold rule's alert has no asset unless `host` is counted (a `latest(host)`
  in the template would fix it); the Splunk-side parameter form for "Send to ArcRadar" (becomes mostly unnecessary
  once phase C fills the parameters).

## Order and size

A is the largest (migration, two endpoints, sync script, form and AI changes, backtest) and the one that most
changes how rules feel. B and C are smaller each. D is a decision for later.
