# Splunk integration

ArcRadar works with Splunk in both directions, the same way it works with Wazuh:

```
 ArcRadar (Detection rules > Splunk rules)             Splunk server
 ───────────────────────────────────────              ──────────────────────────────────────────
  draft ─► read the stanza ─► Send ─► GitHub ◄── arcradar-apply-splunk-rules (pulls, checks, reloads)
                                    splunk/arcradar_<key>.conf        │
                                                                      ▼  saved search runs on a schedule
  alerts, cases, MITRE, AI ◄── POST /api/ingest/splunk ◄── alert action arcradar_forward (bin/arcradar_forward.py)
```

- **Rules out.** An administrator writes a Splunk rule as structured fields (or has the AI draft the fields),
  ArcRadar renders one `savedsearches.conf` stanza from a fixed template, the administrator reads it and sends
  it to the rules repository on GitHub. ArcRadar never connects to Splunk.
- **Alerts in.** The saved search's alert action `arcradar_forward` reports every triggered result to
  `POST /api/ingest/splunk` (API key with the `ingest:splunk` scope). It becomes an event and an alert, like a
  Wazuh alert, with the rule's severity and MITRE ids.

Nothing here executes anything on ArcRadar's side, and nothing but a generated search can be in a rule file:
see "What a rule file can and cannot contain".

## What is in the repository

| Path                                                        | What it is                                                                                            |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `src/lib/siem-rules/`                                       | the rule engine; `dialects/splunk.ts` is the Splunk dialect (spec, renderer, safety check, AI prompt) |
| `src/lib/telemetry/splunk.ts`, `src/app/api/ingest/splunk/` | the ingest adapter and endpoint                                                                       |
| `deploy/splunk/app/arcradar_rules/`                         | the Splunk app: the alert action (`bin/arcradar_forward.py`, `default/alert_actions.conf`)            |
| `deploy/splunk/apply-arcradar-rules.sh`                     | installed on the Splunk host as `arcradar-apply-splunk-rules`                                         |

## Setting it up on a Splunk server (Linux, Splunk Enterprise)

Done on the lab VM (Ubuntu 24.04, Splunk Enterprise 10.0.2 from the `.deb`, `/opt/splunk`, running as `splunk`).

1. **Install the app.** Copy `deploy/splunk/app/arcradar_rules` to `$SPLUNK_HOME/etc/apps/arcradar_rules`, make
   `bin/arcradar_forward.py` executable and give everything to the Splunk user.
2. **Tell it where ArcRadar is.** Create `$SPLUNK_HOME/etc/apps/arcradar_rules/local/arcradar_forward.json`
   (mode 600, owned by the Splunk user):

   ```json
   { "url": "https://<your-arcradar>/api/ingest/splunk", "api_key": "arc_..." }
   ```

   The key is an API key with the `ingest:splunk` scope, made by an administrator on the API keys page. It is
   never part of a saved search or of the rules repository.

3. **Install the apply script.** `install -m 0755 apply-arcradar-rules.sh /usr/local/sbin/arcradar-apply-splunk-rules`
   (needs `git` and `python3`). Put a Splunk admin login as `user:password` in `/etc/arcradar/splunk-admin`
   (mode 600, root only); it is used only to reload the saved searches. Without that file the rules are
   installed and Splunk loads them on its next refresh or restart.
4. **Restart Splunk once** so it reads the new app, then run `arcradar-apply-splunk-rules --check`.
5. **Run it on a schedule**, for example every 10 minutes under `flock` in `/etc/cron.d/arcradar-splunk-rules`,
   the way the Wazuh Manager does it. Settings (repository, branch) are environment variables at the top of the
   script; the default repository is the one ArcRadar commits to.

## What a rule file can and cannot contain

A rule is stored as fields: an index, an optional sourcetype, up to 10 conditions (`field` `contains` / `equals`
/ `regex` `value`), an optional threshold ("N times in M minutes, per these fields") and a schedule.
ArcRadar turns it into

```
[arcradar_1000]
description = Brute force from one address
search = index=main sourcetype=WinEventLog:Security | regex EventCode="(?i)^4625$" | stats count by Source_Network_Address | where count >= 5
enableSched = 1
cron_schedule = */5 * * * *
...
action.arcradar_forward = 1
action.arcradar_forward.param.rule_key = 1000
```

- Values only ever appear inside a quoted, escaped string, as a regular expression. Index, sourcetype and field
  names are matched against strict patterns. `$` and control characters are refused.
- The search is the base search plus `regex`, `stats count` and `where count >= N` segments, nothing else.
  ArcRadar checks its own output (`assertSafeSplunkConf`) and the apply script checks every file again on the
  Splunk host with the same rules, so a file edited by hand on GitHub cannot add `| outputlookup`,
  `| sendalert`, `| script`, `| delete`, a subsearch or any other setting or action. A file that fails is
  refused and nothing is changed.
- The base search is written `index=...`, not `search index=...`: in `savedsearches.conf` Splunk adds the
  `search` command itself, and a second one turns the rule into a search for the word "search". (Found by
  running a rule on a real Splunk.)
- A threshold rule suppresses repeat alerts for the same group for its window (`alert.suppress`), so one burst
  is one alert. A threshold rule's alert only has the fields it counts by: add `host` to "Count per" if the
  alert should name the machine (otherwise it has no asset).

## What reaches ArcRadar

`bin/arcradar_forward.py` runs once per triggered result and sends `{ sid, search_name, results_link,
server_host, result, configuration }` (the action's parameters carry the rule key, name, severity and MITRE
ids). Details and the answer format: [API.md](API.md), "Splunk ingestion". If ArcRadar cannot be reached, the
item is kept in `$SPLUNK_HOME/var/spool/arcradar` (at most 500) and sent with the next one; ArcRadar ignores an
item it already has. Splunk's log shows the action under `component=sendmodalert`
(`index=_internal sourcetype=splunkd component=sendmodalert`).

## Verified on the lab

On Splunk Enterprise 10.0.2 (2026-10-06), end to end against production:

- A rule drafted by the AI in the live ArcRadar ("Five failed Windows logons from the same address within five
  minutes"), sent to GitHub with the button, was pulled by `arcradar-apply-splunk-rules` (cron, real GitHub),
  parsed and reloaded by Splunk, and fired; the alert reached the live ArcRadar as a `high` alert with
  `T1110.001` (and the address as an indicator when it is public).
- A Universal Forwarder on the Windows 10 lab VM (Security log, `sourcetype=WinEventLog:Security`) delivered real
  `EventCode=4625` events (failed SMB logons made with `net use` against loopback) to the Splunk server. Splunk's
  automatic `key: value` extraction already gives `EventCode` and `Source_Network_Address` for the classic
  Windows format, so no add-on is needed for these rules; the rule fired on those real events too.
- With ArcRadar switched off, items went to the spool and were delivered later; a second trigger for the same
  address inside the window was suppressed.

Not covered: Windows events other than the failed-logon ones; Sysmon or XML-rendered logs (different field
names); a threshold rule's alert has no asset unless `host` is among the "Count per" fields.

Operational notes from the lab: Splunk refuses to run searches below 5 GB of free disk (`minFreeSpace`), so the
VM needs a disk of 20 GB or more and room to grow; the apply script takes a lock so a manual run cannot collide
with the cron job.
