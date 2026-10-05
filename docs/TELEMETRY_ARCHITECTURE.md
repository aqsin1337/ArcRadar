# Telemetry architecture: Windows 10 → Wazuh → ArcRadar

Status: **ingestion built in Phase 6b (2026-09-27)**, not yet exercised against a real Wazuh Manager. This
note records the requirement, the rules that keep every phase compatible with it, and what was built. Setup
of a Manager: `docs/WAZUH_INTEGRATION.md`; endpoints: `docs/API.md` ("Telemetry ingestion and API keys").

## Requirement

ArcRadar's telemetry comes from a real Windows 10 machine running a Wazuh Agent; a Wazuh Manager collects
the agent's security events and forwards them to ArcRadar:

```
Windows 10 + Wazuh Agent ──(1)──> Wazuh Manager ──(2)──> ArcRadar app ──> Supabase
```

The main computer is resource-limited and runs ArcRadar (and the local Supabase stack). The Windows 10
machine and the Wazuh Manager run on the user's two other computers, in any split: one each, or both on
one. The machines are **not** assumed to share a computer, a subnet or a network.

## The lab as it is now (told by the user, 2026-09-26)

Everything runs in VMware, and hop 1 already works:

- **Windows 10 client** in a VM on the user's main computer (the one that will also run ArcRadar), with the Wazuh Agent installed and enrolled.
- **Wazuh Manager** in a VM on a friend's computer, joined to the agent over **Tailscale**; the agent's logs reach the Manager without problems.
- The friend's computer is **switched on only on request**, so the Manager is up in sessions, not around the clock. A second friend's computer is unused.
- Decision (advice given, no code): ArcRadar runs **directly on the main computer, not in a VM** (Docker Desktop for local Supabase and the Windows 10 VM already use most of its 15.7 GB of RAM; nginx is a local-only convenience because production is Vercel).
- Hop 2 (Manager → ArcRadar) will use Tailscale until ArcRadar is published, so the **main computer itself needs Tailscale** (so far only the two VMs are known to be on the tailnet) and its address must be reachable by the Manager VM: either `tailscale serve` (HTTPS on the tailnet name, nginx and Next stay on 127.0.0.1) or nginx bound to the Tailscale address with a firewall rule for that interface only.
- After the Vercel deploy the Manager pushes to the public HTTPS URL of ArcRadar, so Tailscale is only needed between the agent and the Manager. ArcRadar is then always up, which removes the main weakness of the lab setup: while the ArcRadar computer is off, a push from the Manager's integration script would be lost. **The delivery script therefore keeps a small retry spool** (built, see below).
- Because the Manager is offline between sessions, the UI shows "last received" per source so that a silent pipeline is visible.

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
  against the installed Wazuh version.

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
6. **Honest health.** ArcRadar sees only what arrives, so a source is "receiving", "quiet" or "never
   delivered", never "connected" or "healthy". Demo feeds are sample data and say so.

## What was built (Phase 6b)

| Piece                | Where                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| API keys             | `src/lib/api-keys/` (`arc_` + 43 characters, SHA-256 hash stored, scope `ingest:wazuh` ↔ permission `events:write`, re-verified on every request)  |
| Route wrapper        | `src/lib/api/ingest-route.ts` (`ingestRoute`): key instead of session, no cookies, no same-origin check                                            |
| Endpoint             | `POST /api/ingest/wazuh` (100 alerts / 1 MiB per request)                                                                                          |
| Adapter              | `src/lib/telemetry/wazuh.ts` (`TelemetrySource`): severity bands, level ≥ 7 raises an alert, ATT&CK ids, asset from the agent, bounded raw payload |
| Indicator extraction | `src/lib/telemetry/extract.ts`: public or documentation addresses, hashes, domains, URLs; never private addresses; verdict always `unknown`        |
| Storage              | `ingest_telemetry()` (migration `20260927110000`): `security definer`, executable only by the service role, one transaction per batch              |
| Idempotency          | unique `(source, source_event_id)` for external events and alerts; `source_event_id` is `<manager name>:<alert id>`                                |
| Assets               | `assets` table (read-only for clients); alerts and events reference it; the alert list also finds alerts by machine name or address                |
| Health               | `telemetry_source_health()` and `src/lib/telemetry/health.ts`; the **Telemetry** page (sources, assets, events)                                    |
| Manager side         | `deploy/wazuh/custom-arcradar` (POSIX `sh` + `curl`, write-ahead spool, retry, set-aside of refused requests), `ossec-integration.xml`             |
| Tooling              | `npm run apikey:create`, `npm run ingest:sample` (fictional alerts, no Manager needed)                                                             |

Decisions that were open when this note was written:

- **Provenance.** Ingested rows are `origin = 'external'` with `source = 'wazuh'`. Only the service role can
  write them (clients can only create `local` rows and cannot relabel), so demo and local data never look
  like live telemetry.
- **Writing without a user JWT.** Through `ingest_telemetry()` only, after the key is verified; the app uses
  the admin client for that one call (and for key creation and audit entries). One `ingest.batch` audit
  entry per request, never per event, never the alerts.
- **Volume.** The Manager config forwards level 7 and up; lower levels are events only and create no
  indicators. There is no retention job yet (Phase 8).
- **Sysmon** and the Wazuh version are still unconfirmed on the lab machines; the adapter reads Sysmon event
  data when it is present and works without it.

## Reaching ArcRadar from the Manager (pick per environment)

| Situation                          | How the Manager reaches ArcRadar                                                                            |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Production                         | The public Vercel URL. No network dependency at all.                                                        |
| Same LAN as the main computer      | The main computer's LAN address (nginx and Next must then listen beyond `127.0.0.1`, plus a firewall rule). |
| Different networks, ArcRadar local | A VPN mesh (Tailscale, WireGuard) or a tunnel (Cloudflare Tunnel) to the main computer.                     |

Today nginx and the local Supabase stack listen on `127.0.0.1` only, which is right for solo development;
widening nginx is a config toggle for the day remote nodes are connected. The agent → Manager hop needs the
same kind of choice between those two machines, independent of ArcRadar.

## Still open

- The delivery script and the `<integration>` options were **not run against a real Manager**: confirm the
  Wazuh version, that the alert file holds one JSON object per line, and that the Manager has `curl`.
- Whether the Manager VM has its own Tailscale address (the agent reaches it, so it should), and how the
  Manager will reach ArcRadar on the main computer until it is published (see the table above).
- Whether Sysmon will be installed (richer process and network events), whether to also surface Wazuh
  vulnerability-detector and SCA results, and the retention period.
- No rate limit on the ingest endpoint yet (Phase 8), and no correlation of repeated alerts beyond their id.
