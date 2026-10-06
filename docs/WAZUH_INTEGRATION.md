# Connecting a Wazuh Manager to ArcRadar

The Manager **pushes** each alert to ArcRadar's ingest endpoint. ArcRadar never polls Wazuh and stores no
Wazuh credentials. Design and rules: `docs/TELEMETRY_ARCHITECTURE.md`. Endpoint details: `docs/API.md`
("Telemetry ingestion").

```
Windows 10 + Wazuh Agent ──> Wazuh Manager ──(custom-arcradar, HTTPS + API key)──> ArcRadar ──> Supabase
```

> **Verified on a lab.** Wazuh Manager 4.14.8 on Ubuntu 24.04 with a Windows 10 agent, sending to an
> ArcRadar deployed on Vercel: a burst of failed Windows logons (Wazuh rule 60204, level 10, technique
> T1110) arrived as an alert with its machine and technique. Research on arrival was checked separately,
> with an ingested alert that carried a public address: VirusTotal and AbuseIPDB answered within seconds.
> Other Wazuh versions should behave the same; check the `<integration>` options against yours
> (`/var/ossec/bin/wazuh-control info`).

## What you need

- A running ArcRadar the Manager can reach (see "Reaching ArcRadar" below).
- An **administrator** account in ArcRadar: only an administrator can create a key with the `ingest:wazuh`
  scope (the permission behind it is `events:write`).
- On the Manager: `sh`, `awk`, `sort`, `date` and **`curl`** (the script says so in the log if `curl` is missing).

## 1. Create an API key

In ArcRadar, signed in as an administrator, open **API keys**, press **New key**, give it a name (for
example "Wazuh Manager"), choose the scope **Send Wazuh alerts to ArcRadar** and a lifetime.

The key (`arc_` followed by 43 characters) is shown **once**. ArcRadar keeps only its SHA-256 hash, so a
lost key cannot be shown again: revoke it (`DELETE /api/api-keys/:id`) and make another. A key stops working
the moment it is revoked, expires, or its owner is disabled or loses the permission. Give each Manager its
own key, a short lifetime while you experiment, and never commit it or paste it into a chat.

<details>
<summary>From the command line instead</summary>

From the ArcRadar project folder (the password is read from the environment, never from the command line):

```powershell
$env:ARCRADAR_EMAIL = "you@example.com"      # your administrator
$env:ARCRADAR_PASSWORD = "..."
npm run apikey:create -- --url https://YOUR-ARCRADAR --name "Wazuh Manager" --days 90
```

</details>

## 2. Try the pipeline without a Manager (optional)

From the ArcRadar project folder on any computer:

```powershell
npm run ingest:sample -- --url https://YOUR-ARCRADAR --key arc_...
npm run ingest:sample -- --replay          # the same alerts again: nothing new is created
```

This sends fictional alerts (manager `sample-manager`, agents `SAMPLE-*`). Open **Telemetry** in ArcRadar:
the Wazuh card turns to "Receiving", the machines appear under Assets, and alerts of level 7 and up appear
on **Alerts** with their machine and ATT&CK techniques. The sample data is real ingested data in every
respect (origin "External provider"); delete it from the database when you no longer want it.

## 3. Install the script on the Manager

Copy `deploy/wazuh/custom-arcradar` to the Manager and install it where Wazuh looks for integrations:

```sh
sudo install -o root -g wazuh -m 750 custom-arcradar /var/ossec/integrations/custom-arcradar
```

The name must start with `custom-` and match the `<name>` below. Owner `root`, group `wazuh`, mode `750`
is what Wazuh's own integration scripts use.

## 4. Configure the integration

Add the block from `deploy/wazuh/ossec-integration.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`, with your URL and key:

```xml
<integration>
  <name>custom-arcradar</name>
  <hook_url>https://YOUR-ARCRADAR/api/ingest/wazuh</hook_url>
  <api_key>arc_...</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

- `<level>7</level>`: ArcRadar turns Wazuh level 7 and up into alerts. Lower levels only ever become
  **events** (context on the Telemetry page, no alert, no indicators). Start at 7 to keep the volume small
  (the free Supabase tier is limited); lower it (say 3) only if you want the lower-level events too.
- `ossec.conf` now holds a secret: keep it readable by `root` and `wazuh` only (Wazuh's default).
- Restart the Manager: `sudo systemctl restart wazuh-manager`.

The script is given `<alert_file> <api_key> <hook_url>` by Wazuh. It writes each alert to a small spool
(`/var/ossec/tmp/arcradar-spool`) and then sends the spool, oldest first.

| Situation                                         | What the script does                                                                            |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| ArcRadar answers 2xx                              | The alert is removed from the spool.                                                            |
| ArcRadar is off, unreachable, or answers 5xx      | The alert stays and is sent on a later run (a computer switched off for a while loses nothing). |
| 401 or 403 (key refused; or missing the scope)    | Alerts are kept and a line says so; they go out once the key in `ossec.conf` is fixed.          |
| 400, 413, 415, 422 (ArcRadar can never accept it) | The request is moved to `rejected/` (the newest 50 are kept) so it does not block the others.   |
| More than 500 alerts waiting                      | The oldest are dropped, with a note in the log.                                                 |

A resend is harmless: ArcRadar ignores an alert it already has (same manager name and alert id).
Environment variables can change the spool location, log file and limits (see the script's header).

## 5. Check that it works

- On the Manager: `sudo tail -f /var/ossec/logs/integrations.log` (the script's messages, prefixed
  `custom-arcradar:`) and `/var/ossec/logs/ossec.log` (integratord).
- In ArcRadar: **Telemetry**. The Wazuh card says "Receiving" when something arrived in the last 15 minutes
  and "Quiet" after that. ArcRadar only sees what arrives, so it never says "connected": a Manager that is
  switched off simply goes quiet. The demo feeds are labelled "Demo feed" and never count as receiving.
- Make an alert on purpose, for example several failed logons on the Windows 10 machine, and look on
  **Alerts** (source `wazuh`, origin "External provider").

## What ArcRadar keeps

For each alert: an **event** (always), and for level 7+ an **alert** with the machine (**asset**, made from the
agent), the ATT&CK techniques named in the rule, and up to five **indicators** taken from the alert (public or
documentation IP addresses, file hashes, domains, URLs; never private addresses or internal names). Indicators
made this way start with the verdict "unknown": a sensor saw them, nobody has judged them. Right after the
delivery is stored, ArcRadar looks up the new public ones at the intelligence providers that are switched on
and records the worst verdict it finds (at most four per delivery; a verdict only ever moves up). A tracked indicator that
already exists (any origin) is linked, never changed. A bounded copy of the raw alert (16 KiB, raw log line
first) is kept with the event and shown on the alert page. Every batch writes one `ingest.batch` audit entry
(who sent it, how many of each outcome; never the alerts).

Ingested rows are labelled origin "External provider" and their source is `wazuh`. Demo and local data are
never mistaken for them, and the database enforces that clients cannot create or relabel such records.

## Reaching ArcRadar

| Situation                            | `hook_url`                                                                                                                                                                  |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Published (Vercel)                   | `https://<your address>/api/ingest/wazuh`. No network dependency.                                                                                                           |
| ArcRadar on your computer, Tailscale | The computer's tailnet name over HTTPS with `tailscale serve`, or its `100.x` address (plain `http` is accepted for `100.*` and `*.ts.net`, since the tunnel is encrypted). |
| Same LAN                             | The computer's LAN address. nginx and Next listen on `127.0.0.1` only today: widening that needs a config change and a firewall rule.                                       |

The script warns in its log when `hook_url` is plain `http` outside `localhost` and the private tunnel range,
because the key and the alerts would then cross the network unencrypted.

## Troubleshooting

| You see                                | Cause                                                                                                                                                                                                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `curl is not installed on this host`   | Install `curl` on the Manager.                                                                                                                                                                                                                            |
| `HTTP 000`                             | Nothing answered: wrong `hook_url`, ArcRadar off, firewall, or the tunnel is down. Alerts wait.                                                                                                                                                           |
| `HTTP 401`                             | The key is wrong, revoked or expired, or its owner was disabled or is no longer an administrator (ArcRadar gives the same answer for all of these). Make a new key (step 1).                                                                              |
| `HTTP 403`                             | A valid key that lacks the `ingest:wazuh` scope.                                                                                                                                                                                                          |
| `HTTP 400` / `422`, request set aside  | ArcRadar refused the request for good. Look in `/var/ossec/tmp/arcradar-spool/rejected/`. `400` includes a body that is not JSON (for example if the Manager writes an alert over several lines: report it, the script expects one JSON object per line). |
| Wazuh card stays "No events yet"       | `integrations.log` shows nothing: check `<name>`, the file's owner and mode, `<level>`, that `alert_format` is `json`, and restart the Manager.                                                                                                           |
| Alerts arrive but no **alert** appears | Their level is below 7: they are events. See the Events table on **Telemetry**.                                                                                                                                                                           |
| The batch is "partly rejected"         | The response lists the alerts ArcRadar could not use and why (each rejected alone; the rest are stored).                                                                                                                                                  |

## Limits worth knowing

- The endpoint accepts up to 100 alerts and 1 MiB per request, and 120 requests a minute per key.
- A repeat of an alert (same rule title, machine and indicator, within 60 minutes, while the first is still
  open) is linked to the first one as a duplicate instead of opening a new alert. The alert list hides
  duplicates unless you ask for them.
- The machine's operating system is inferred only for Windows event data; other systems show no OS.
- Retention is not built: Wazuh is chatty, so watch the size of the `events` table on a free tier.
