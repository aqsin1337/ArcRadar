# Telemetry architecture: Windows 10 → Wazuh → ArcRadar

Status: design note (2026-09-26). Nothing here is built yet. It records the requirement and the rules that
keep every later phase compatible with it. No decision about which computer runs what is needed yet.

## Requirement

ArcRadar's telemetry comes from a real Windows 10 machine running a Wazuh Agent; a Wazuh Manager collects
the agent's security events and forwards them to ArcRadar:

```
Windows 10 + Wazuh Agent ──(1)──> Wazuh Manager ──(2)──> ArcRadar app ──> Supabase
```

The main computer is resource-limited and runs ArcRadar (and the local Supabase stack). The Windows 10
machine and the Wazuh Manager run on the user's two other computers, in any split: one each, or both on
one. The machines are **not** assumed to share a computer, a subnet or a network.

## Facts that shape the design (checked against the Wazuh docs)

- The Wazuh **Manager is Linux-only** (Ubuntu, RHEL, Amazon Linux, ...). Windows only gets the **Agent**.
  So "Windows 10 + Wazuh" means a Windows 10 endpoint with the agent, plus a Linux host, VM or container for
  the Manager. Both can sit on one physical computer (Manager in a VM) if its resources allow.
- ArcRadar needs only the **Manager**. The Wazuh Indexer and Dashboard (which drive the official 4 vCPU /
  8 GiB all-in-one sizing) are not required, which keeps the Manager node light.
- Hop 1 is **agent-initiated**: the agent connects to the Manager on TCP 1514 (events) and 1515 (enrollment).
- Wazuh's `<integration>` block (Manager `ossec.conf`) can run a `custom-*` script from
  `/var/ossec/integrations/` for each alert at or above a configured `level` (also filterable by `rule_id`
  or `group`, `alert_format` json). The script receives the alert file path, an `api_key` and a `hook_url`
  from the config. That is a supported way to push alerts straight to a URL. Re-check the exact options
  against the installed Wazuh version when implementing.

## Design rules

1. **Topology independence.** Each node knows its neighbour only through configuration (a URL, a key, a
   host name). No address, host name or OS is baked into ArcRadar code. Sensor-side hops are initiated by
   the sensor side (agent → Manager, Manager → ArcRadar), so the machines behind them need no inbound path.
2. **Push, not pull, by default.** The Manager pushes alerts to an ArcRadar ingest endpoint over HTTPS. This
   works with the production target (Vercel: stateless request/response, no worker, and the app has a public
   URL) and with a local ArcRadar on the main computer. Polling the Wazuh API (55000) or Indexer (9200) from
   ArcRadar would need ArcRadar to reach the Wazuh network, store Wazuh credentials and run a scheduler; keep
   it only as an optional adapter for LAN development, behind the same interface.
3. **Remote nodes only ever talk to the ArcRadar app**, never to Supabase. The service-role key and database
   stay on the ArcRadar side.
4. **ArcRadar authenticates the sender**, not the network: an ArcRadar-issued API key (hash stored, scoped,
   revocable) rides in the request; TLS outside localhost; bounded, validated, idempotent batches.
5. **Telemetry is not enrichment.** Two abstractions, one shared vocabulary: `IntelProvider` (outbound
   lookups: VirusTotal, AbuseIPDB, ...) and `TelemetrySource` (inbound events: Wazuh first, others later).
   Each record keeps its provenance and the UI labels it.

## Planned ArcRadar side (later phase, not decided)

- **Ingest endpoint** `POST /api/ingest/wazuh` taking a batch of Wazuh alert JSON. A third route wrapper
  (`ingestRoute`, next to `publicRoute` / `protectedRoute`) authenticates the API key instead of a session:
  no cookies, so the same-origin check does not apply. Zod-validated, size-limited, rate-limited (Phase 8
  store), idempotent by a `source_event_id` unique key so retries and duplicates are harmless.
- **API keys** come from the existing `api_keys` table (creation and verification are Phase 7 work) with a
  scope such as `ingest:wazuh`. Writing without a user JWT means the service role, so keep it behind a narrow
  repository (or a `SECURITY DEFINER` function callable only by `service_role`) that can only insert events,
  alerts and indicators after the key is verified. Audit one `ingest.batch` entry per request, not per event.
- **Normalization** in a `wazuh` adapter: `rule.level` → severity, `rule.mitre.id` → `mitre_techniques`,
  `rule.groups` → tags, `agent.*` → the asset, IPs/hashes/domains in `data.win.eventdata` → indicators,
  a bounded copy of the raw alert kept in `payload` for investigations.
- **Provenance is already enforced for indicators** (migration `20260926120000`): signed-in users can only create `origin = 'local'` records and nobody can relabel one, so ingested telemetry must be written with the service role (server side, after the API key is verified), which is the only path that may record `origin = 'external'`. Give events and alerts the same treatment when the ingest work starts.
- **Already in the schema:** `events` and `alerts` have `source` (text, default `manual`), `origin`,
  `severity`, `occurred_at` and, for events, a `payload jsonb` that can hold the bounded raw alert. Ingested
  rows have no `created_by` (it is nullable), which is correct for a machine sender.
- **Schema additions needed** (new migrations, with RLS and DB tests): a `source_event_id` on events and
  alerts with a unique index on `(source, source_event_id)` for idempotency; an `assets` table (agent id,
  name, OS, last seen) and a reference to it; a `wazuh` row in `integrations` plus a `telemetry` capability
  (the current check constraint does not allow it). How `origin` reads for live sensor data (`external`
  with `source = 'wazuh'` is the likely fit) is decided then; demo and local data must still never look
  like live telemetry.
- **Volume:** Wazuh is chatty and Supabase storage is limited. Start with `level >= 7` in the Manager
  config, and add a retention job in Phase 8.
- **Connector health:** surface "last event received" per source so a silent pipeline is visible.

## Reaching ArcRadar from the Manager (pick per environment, later)

| Situation                          | How the Manager reaches ArcRadar                                                                            |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Production                         | The public Vercel URL. No network dependency at all.                                                        |
| Same LAN as the main computer      | The main computer's LAN address (nginx and Next must then listen beyond `127.0.0.1`, plus a firewall rule). |
| Different networks, ArcRadar local | A VPN mesh (Tailscale, WireGuard) or a tunnel (Cloudflare Tunnel) to the main computer.                     |

Today nginx and the local Supabase stack listen on `127.0.0.1` only, which is right for solo development;
widening nginx is a config toggle for the day remote nodes are connected. The agent → Manager hop needs the
same kind of choice between those two machines, independent of ArcRadar.

## Impact on current code and phases

- **Nothing to change now.** Server-to-server requests carry no `Origin`, so they already pass the CSRF
  check; the `events`, `alerts`, `indicators`, `mitre_techniques` and `api_keys` tables and the
  `events:write` permission already anticipate this.
- **Phase 3 (UI):** design the events/alerts views so a record can show its source and provenance label and
  an asset name; no ingestion work.
- **Ingestion depends on API-key auth (Phase 7).** Proposal, to be decided when the time comes: either build
  the Wazuh integration right after Phase 7, or pull API-key creation and the `ingestRoute` wrapper forward.

## Open questions (no answer needed yet)

Wazuh version; whether the Windows 10 endpoint is physical or a VM; whether Sysmon will be installed (richer
process/network events); Manager on a Linux VM, Docker or WSL2; the alert level to forward; whether to also
surface Wazuh vulnerability-detector and SCA results; retention period.
