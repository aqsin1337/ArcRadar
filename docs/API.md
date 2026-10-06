# ArcRadar API conventions

Every endpoint is a Next.js Route Handler under `src/app/api/`. Domain endpoints (indicators, intelligence
lookups, vulnerabilities, alerts, investigations, threat intelligence, telemetry ingestion, reports and
dashboard, and administration: API keys, integrations, users, audit log) follow the rules below.

## Envelope and errors

Every JSON response has the same shape (`src/lib/api/response.ts`):

```json
{ "success": true, "data": { "...": "..." }, "error": null }
{ "success": false, "data": null, "error": { "code": "FORBIDDEN", "message": "...", "details": {} } }
```

Every response carries `Cache-Control: no-store` and an `x-request-id` header (also written to the server
log for unexpected errors). Field names in JSON are `snake_case`, matching the database.

| Status | `error.code`                                           | Meaning                                                       |
| ------ | ------------------------------------------------------ | ------------------------------------------------------------- |
| 400    | `BAD_REQUEST`                                          | Malformed body (empty, invalid JSON or UTF-8)                 |
| 401    | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`               | No/invalid session, or wrong email or password                |
| 403    | `FORBIDDEN`, `ACCOUNT_DISABLED`, `EMAIL_NOT_CONFIRMED` | Missing permission, cross-origin request, disabled account    |
| 404    | `NOT_FOUND`                                            | Unknown endpoint or record                                    |
| 409    | `CONFLICT`                                             | Unique/foreign-key conflict                                   |
| 413    | `PAYLOAD_TOO_LARGE`                                    | JSON body over 64 KB                                          |
| 415    | `UNSUPPORTED_MEDIA_TYPE`                               | Body is not `application/json`                                |
| 422    | `VALIDATION_ERROR`                                     | `details.issues` = `[{ path, message }]`, no echoed values    |
| 429    | `RATE_LIMITED`                                         | Supabase Auth's own limit, or this app's; see "Rate limiting" |
| 500    | `INTERNAL_ERROR`                                       | Unexpected; details are only in the server log                |
| 503    | `DEPENDENCY_UNAVAILABLE`                               | Supabase unreachable or the app is not configured             |

Lists return `{ items, pagination: { page, page_size, total, total_pages } }` and accept
`?page=1&page_size=25` (`page_size` max 100).

## Endpoints

| Method           | Path                                                         | Access                           | Notes                                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------ | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET              | `/api/health`                                                | public                           | Liveness + Supabase reachability, no config values                                                                                                                                                                                      |
| POST             | `/api/auth/login`                                            | public                           | `{ email, password }`; sets session cookies; returns `me`                                                                                                                                                                               |
| POST             | `/api/auth/logout`                                           | public                           | Ends the current session; succeeds when already signed out                                                                                                                                                                              |
| POST             | `/api/auth/signup`                                           | public                           | `{ email, password, display_name? }`; always `201`, see below                                                                                                                                                                           |
| POST             | `/api/auth/forgot-password`                                  | public                           | `{ email }`; always `200 { sent: true }`                                                                                                                                                                                                |
| POST             | `/api/auth/update-password`                                  | signed in                        | `{ password }`; revokes the user's other sessions                                                                                                                                                                                       |
| GET              | `/api/auth/me`                                               | signed in                        | `{ user, profile: { display_name, role }, permissions }`                                                                                                                                                                                |
| PATCH            | `/api/auth/me`                                               | signed in                        | `{ display_name?, avatar_url? }`; `""` clears a field, `undefined` leaves it; at least one required                                                                                                                                     |
| GET              | `/api/audit-logs`                                            | `audit:read` (admin)             | Filters: `action`, `user_id`, `entity_type`, `entity_id`, `from`, `to`                                                                                                                                                                  |
| GET              | `/auth/callback`                                             | public (email links)             | Exchanges the emailed `code`, redirects to a same-site `next`                                                                                                                                                                           |
| GET              | `/api/indicators`                                            | `indicators:read`                | Search, filter, sort, paginate; see below                                                                                                                                                                                               |
| POST             | `/api/indicators`                                            | `indicators:write`               | Creates a local indicator; `409` names a duplicate                                                                                                                                                                                      |
| GET              | `/api/indicators/:id`                                        | `indicators:read`                | With tags, linked entities and relationships                                                                                                                                                                                            |
| PATCH            | `/api/indicators/:id`                                        | `indicators:write`               | Fields and tags; type and value are fixed                                                                                                                                                                                               |
| DELETE           | `/api/indicators/:id`                                        | `indicators:delete`              | Admins                                                                                                                                                                                                                                  |
| GET              | `/api/search`                                                | signed in                        | Global search across readable record types                                                                                                                                                                                              |
| GET              | `/api/intel/:kind`                                           | `indicators:read`                | Look up an IP, domain, URL or hash (`kind`: `ip domain url hash`)                                                                                                                                                                       |
| GET              | `/api/vulnerabilities`                                       | `vulnerabilities:read`           | Search, filter, sort, paginate CVEs; see below                                                                                                                                                                                          |
| GET              | `/api/vulnerabilities/stats`                                 | `vulnerabilities:read`           | Record counts per severity and how many are exploited                                                                                                                                                                                   |
| GET              | `/api/vulnerabilities/:cve`                                  | `vulnerabilities:read`           | One CVE with affected products and the indicator that tracks it                                                                                                                                                                         |
| POST             | `/api/vulnerabilities/import`                                | `vulnerabilities:write`          | Fetch a CVE from the connected provider (NVD) and record it                                                                                                                                                                             |
| POST             | `/api/indicators/:id/relationships`                          | `indicators:write`               | Relate this indicator to another; `DELETE .../relationships/:relationshipId` removes one                                                                                                                                                |
| GET              | `/api/indicators/:id/ai`                                     | `indicators:read`                | The latest AI analysis per kind for this indicator, plus a short history; see "AI analysis"                                                                                                                                             |
| POST             | `/api/indicators/:id/ai`                                     | `ai:use` + `indicators:read`     | `{ kind: "verdict_recommendation" }`; no side effect — applying it is a normal `PATCH` the analyst makes                                                                                                                                |
| GET              | `/api/alerts`                                                | `alerts:read`                    | Search, filter, sort, paginate alerts; see below                                                                                                                                                                                        |
| POST             | `/api/alerts`                                                | `alerts:write`                   | Creates a manual, local alert                                                                                                                                                                                                           |
| GET              | `/api/alerts/stats`                                          | `alerts:read`                    | Alerts per status and how many nobody has picked up                                                                                                                                                                                     |
| GET              | `/api/alerts/:id`                                            | `alerts:read`                    | With indicator, event, assignee, investigations, matched rule and duplicate links                                                                                                                                                       |
| PATCH            | `/api/alerts/:id`                                            | `alerts:write`                   | `{ status?, assigned_to? }`; the lifecycle is enforced (`409`)                                                                                                                                                                          |
| DELETE           | `/api/alerts/:id`                                            | `alerts:delete`                  | Admins                                                                                                                                                                                                                                  |
| GET              | `/api/alerts/:id/ai`                                         | `alerts:read`                    | The latest AI analysis per kind for this alert, plus a short history; see "AI analysis"                                                                                                                                                 |
| POST             | `/api/alerts/:id/ai`                                         | `ai:use` + `alerts:read`         | `{ kind }`; asks the active AI provider, validates and stores the answer; `503` with none configured                                                                                                                                    |
| GET              | `/api/alerts/:id/response-actions`                           | `alerts:read`                    | Every recommendation/execution logged for this alert; see "Response orchestration"                                                                                                                                                      |
| POST             | `/api/alerts/:id/response-actions`                           | `alerts:write`                   | `{ action_id }`; recommends an existing catalog action (`source: "analyst"`, starts `recommended`)                                                                                                                                      |
| PATCH            | `/api/alerts/:id/response-actions/:logId`                    | `alerts:write`                   | `{ status, notes? }`; moves it forward only (`409` for a move the workflow does not allow)                                                                                                                                              |
| DELETE           | `/api/alerts/:id/response-actions/:logId`                    | `alerts:write`                   | Removes a mistaken recommendation                                                                                                                                                                                                       |
| GET              | `/api/investigations`                                        | `investigations:read`            | Search, filter, sort, paginate; see below                                                                                                                                                                                               |
| POST             | `/api/investigations`                                        | `investigations:write`           | Opens a local investigation, optionally with tags, indicators, alerts                                                                                                                                                                   |
| GET              | `/api/investigations/stats`                                  | `investigations:read`            | Investigations per status                                                                                                                                                                                                               |
| GET              | `/api/investigations/:id`                                    | `investigations:read`            | With indicators, alerts, notes, evidence and the timeline                                                                                                                                                                               |
| PATCH            | `/api/investigations/:id`                                    | `investigations:write`           | Status, priority, analyst, title, description, tags                                                                                                                                                                                     |
| DELETE           | `/api/investigations/:id`                                    | `investigations:delete`          | Admins                                                                                                                                                                                                                                  |
| POST             | `/api/investigations/:id/{indicators,alerts,notes,evidence}` | `investigations:write`           | Attach an indicator or alert, add a note or evidence; the item is removed with `DELETE .../:itemId` (notes also `PATCH`)                                                                                                                |
| GET              | `/api/investigations/:id/ai`                                 | `investigations:read`            | The latest AI analysis per kind for this investigation, plus a short history; see "AI analysis"                                                                                                                                         |
| POST             | `/api/investigations/:id/ai`                                 | `ai:use` + `investigations:read` | `{ kind: "investigation_checklist" }`; also seeds trackable checklist items                                                                                                                                                             |
| GET              | `/api/investigations/:id/checklist`                          | `investigations:read`            | Every checklist item, oldest first; see "Investigation checklists"                                                                                                                                                                      |
| POST             | `/api/investigations/:id/checklist`                          | `investigations:write`           | `{ text }`; adds an item by hand (`source: "analyst"`)                                                                                                                                                                                  |
| PATCH            | `/api/investigations/:id/checklist/:itemId`                  | `investigations:write`           | `{ done }`; the server stamps who and when                                                                                                                                                                                              |
| DELETE           | `/api/investigations/:id/checklist/:itemId`                  | `investigations:write`           | Removes an item                                                                                                                                                                                                                         |
| GET              | `/api/mitre`, `/api/mitre/:id`                               | `threat_intel:read`              | The ATT&CK matrix with what your alerts named; one technique (`T1566`) with the alerts that name it; see "MITRE ATT&CK"                                                                                                                 |
| POST             | `/api/ingest/wazuh`                                          | API key `ingest:wazuh`           | A Wazuh Manager pushes alerts; no session, no cookies; see "Telemetry ingestion"                                                                                                                                                        |
| POST             | `/api/ingest/splunk`                                         | API key `ingest:splunk`          | A Splunk server pushes triggered saved-search results; same behavior as the Wazuh endpoint; see "Splunk ingestion"                                                                                                                      |
| POST             | `/api/ingest/splunk/catalog`                                 | API key `ingest:splunk`          | The Splunk host reports its real fields: `{ sources: [ { index, sourcetype, window_hours, events_sampled, fields: [ { name, count, distinct?, values? } ] } ] }`; each source's earlier report is replaced; see "Splunk field catalog"  |
| POST             | `/api/ingest/splunk/backtests`                               | API key `ingest:splunk`          | The Splunk host reports what each ArcRadar rule's search found on past data: `{ results: [ { rule_key, window_hours (24 or 168), kind, matches, scanned?, sample?, search_sha256, error? } ] }`; see "Rule mode and backtests"          |
| GET              | `/api/ingest/splunk/wake`                                    | API key `ingest:splunk`          | The Splunk host waits here (`?since=<revision>&wait=0-25`) and is answered `{ revision, changed }` when a rule is pushed; see "Rule mode and backtests"                                                                                 |
| GET              | `/api/api-keys`                                              | `api_keys:manage_own`            | Your keys (an administrator sees every key); never the key itself or its hash                                                                                                                                                           |
| POST             | `/api/api-keys`                                              | `api_keys:manage_own`            | `{ name, scopes, expires_in_days? }`; the key is in the response **once**; the `ingest:wazuh` scope needs an administrator                                                                                                              |
| DELETE           | `/api/api-keys/:id`                                          | `api_keys:manage_own`            | Revokes a key (yours, or any for an administrator); revoking twice is harmless                                                                                                                                                          |
| GET              | `/api/telemetry/sources`                                     | `events:read`                    | Every telemetry source with its status (receiving, quiet, never, demo) and last delivery                                                                                                                                                |
| GET              | `/api/events`                                                | `events:read`                    | Filters `source`, `severity`, `origin`, `asset`; sort `occurred_at`, `created_at`, `severity`; paginated                                                                                                                                |
| GET              | `/api/assets`                                                | `events:read`                    | Machines that report telemetry; filters `source`, `origin`; sort `last_seen`, `name`, `first_seen`                                                                                                                                      |
| GET              | `/api/dashboard`                                             | signed in                        | `?days&severity`; counts, distributions, activity series, the most-seen ATT&CK techniques and malicious indicators, recent records; see "Dashboard"                                                                                     |
| GET              | `/api/reports`                                               | `reports:read`                   | `?q&type`; search by title, filter by type, newest first                                                                                                                                                                                |
| POST             | `/api/reports`                                               | `reports:write`                  | `{ type, title?, ...fields the type needs }`; generates and stores a snapshot; see "Reports"                                                                                                                                            |
| GET              | `/api/reports/:id`                                           | `reports:read`                   | The generated snapshot (`content`) and the inputs it was made from (`parameters`)                                                                                                                                                       |
| DELETE           | `/api/reports/:id`                                           | `reports:write`                  | Any holder may delete any report (like the other write actions)                                                                                                                                                                         |
| GET              | `/api/integrations`                                          | `integrations:read`              | Every provider, whether a key is configured, and whether it is enabled; never a key value                                                                                                                                               |
| PATCH            | `/api/integrations/:provider`                                | `integrations:manage`            | `{ enabled }`; the demo provider cannot be turned off; `404` for an unknown provider                                                                                                                                                    |
| GET              | `/api/ai/settings`                                           | `ai:use`                         | Every AI-capable provider, whether configured/enabled, and which one (if any) is active; see "AI analysis"                                                                                                                              |
| PATCH            | `/api/ai/settings`                                           | `ai:manage` (admin)              | `{ active_provider, active_model }`; the provider must be configured and enabled; `409` otherwise                                                                                                                                       |
| GET              | `/api/response-actions`                                      | `alerts:read`                    | The response-action catalog; see "Response orchestration"                                                                                                                                                                               |
| POST             | `/api/response-actions`                                      | `investigations:write`           | `{ title, description?, category? }`; adds a local catalog entry                                                                                                                                                                        |
| PATCH            | `/api/response-actions/:id`                                  | `investigations:write`           | Edits a catalog entry's fields                                                                                                                                                                                                          |
| DELETE           | `/api/response-actions/:id`                                  | `investigations:write`           | `409` if an alert has already recommended or logged it                                                                                                                                                                                  |
| GET              | `/api/detection-rules`                                       | `alerts:read`                    | The rule catalog; see "Detection rules and alert deduplication"                                                                                                                                                                         |
| POST             | `/api/detection-rules`                                       | `rules:manage` (admin)           | `{ id, name, description?, conditions, severity?, priority?, enabled? }`; `id` is 100000-999999                                                                                                                                         |
| PATCH            | `/api/detection-rules/:id`                                   | `rules:manage` (admin)           | Edits a rule's fields; the id itself is fixed                                                                                                                                                                                           |
| DELETE           | `/api/detection-rules/:id`                                   | `rules:manage` (admin)           | Any alert it had matched keeps its history; only `matched_rule_id` is cleared                                                                                                                                                           |
| GET              | `/api/wazuh-rules`                                           | `rules:manage` (admin)           | Wazuh detection rules with their generated XML and trigger counts; see "Wazuh rules"                                                                                                                                                    |
| POST             | `/api/wazuh-rules`                                           | `rules:manage` (admin)           | `{ id?, name, description?, level, parent_kind, parent_value, conditions, mitre_ids? }`; always a draft, next free id when `id` is omitted                                                                                              |
| POST             | `/api/wazuh-rules/generate`                                  | `rules:manage` + `ai:use`        | `{ prompt }`; the active AI provider drafts a rule (checked like a hand-written one), stored as an AI-sourced draft; `503` when no provider is ready                                                                                    |
| GET/PATCH/DELETE | `/api/wazuh-rules/:id`                                       | `rules:manage` (admin)           | Read, edit fields (never the id), delete a draft or rejected rule (`409` for a pushed one)                                                                                                                                              |
| POST             | `/api/wazuh-rules/:id/reject`                                | `rules:manage` (admin)           | `{ reason? }`; a draft becomes rejected (`409` otherwise)                                                                                                                                                                               |
| POST             | `/api/wazuh-rules/:id/push`                                  | `rules:manage` (admin)           | Commits `rules/arcradar_<id>.xml` to the rules repository; `503` when GitHub is not configured or refuses the token, `409` for a rejected rule                                                                                          |
| GET/POST         | `/api/siem-rules/:siem`                                      | `rules:manage` (admin)           | Rules for another SIEM (`splunk` today; unknown SIEM is `404`). POST `{ rule_key?, name, description?, severity, mitre_ids?, spec }`; `spec` is that SIEM's strict structured fields; always a draft; GET lists with the generated file |
| POST             | `/api/siem-rules/:siem/generate`                             | `rules:manage` + `ai:use`        | `{ prompt }`; the AI drafts a `spec`, checked like a hand-written rule; `503` when no provider is ready                                                                                                                                 |
| GET/PATCH/DELETE | `/api/siem-rules/:siem/:id`                                  | `rules:manage` (admin)           | `:id` is a uuid. Edit fields (never the SIEM or the key; a `spec` replaces the whole spec); delete a draft or rejected rule (`409` for a pushed one)                                                                                    |
| POST             | `/api/siem-rules/:siem/:id/reject`, `.../push[?mode=test     | live]`                           | `rules:manage` (admin)                                                                                                                                                                                                                  | Reject a draft; commit the generated file (`splunk/arcradar_<key>.conf`) to the rules repository (`503` when GitHub is not configured) |
| GET              | `/api/siem-rules/:siem/fields`                               | `rules:manage` (admin)           | The fields the SIEM host reported (`?index=&sourcetype=` narrows): per source how often each field appears and a few example values; empty until it has reported                                                                        |
| GET              | `/api/users`                                                 | `users:read` (admin)             | Every account (email, role, active, last sign-in); needs the service role to read `auth.users`                                                                                                                                          |
| POST             | `/api/users`                                                 | `users:manage` (admin)           | `{ email, password, display_name, role_name }`; makes an account that is active at once, with no confirmation mail; `409` when the email already has one; rate limited per caller                                                       |
| PATCH            | `/api/users/:id`                                             | `users:manage` (admin)           | `{ role_name?, is_active? }`; `409` on your own account or on the last active administrator                                                                                                                                             |
| any              | `/api/<unknown>`                                             | -                                | `404` in the envelope (`src/app/api/[...path]`)                                                                                                                                                                                         |

Auth behavior worth knowing:

- **No account enumeration.** Wrong password and unknown email give the same `401`; sign-up answers `201`
  for new and existing emails alike and never signs the caller in (they sign in next); forgot-password
  always answers `200`.
- **New accounts are `viewer`.** The role is set by a database trigger and never read from the request;
  bodies are strict, so an extra `role_name` field is a `422`. Promotion is an admin action (Phase 7) or SQL.
- **Disabled accounts** (`profiles.is_active = false`) get `403 ACCOUNT_DISABLED` on every guarded call, even
  with a live session, and cannot sign in.
- **CSRF.** Unsafe methods reject a browser `Origin` that differs from the request host; bodies must be JSON;
  the auth cookies are `SameSite=Lax`, `HttpOnly` and, in production, `Secure`
  (`src/lib/supabase/cookie-options.ts`; the browser client is not used anywhere, so nothing needs
  JavaScript access to the cookie).

## Rate limiting

Vercel functions keep no memory between invocations and there is no second store (decision 1), so every
app-level limit is a shared counter in Postgres: `check_rate_limit()` (`security definer`, service-role only)
does one atomic upsert per call against a small `rate_limit_buckets` table, keyed by `<route class>:<subject>`.
`src/lib/rate-limit/` wraps it as `enforceRateLimit()`, wired into `publicRoute`/`protectedRoute`/`ingestRoute`
as an optional `rateLimit` option checked once the caller is known (after the permission check, so a denied
request never spends a bucket slot) and before the handler runs. It **fails open**: a broken limiter (a
database hiccup) logs and lets the request through rather than turning an outage into every request being
refused, the same posture `writeAuditLog` already takes for audit writes.

| Route class        | Limit          | Keyed by         | Covers                                                                                                                                                                                          |
| ------------------ | -------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authByIp`         | 30 / 5 minutes | Caller's IP      | `POST /api/auth/{login,signup,forgot-password}` (matches Supabase Auth's own `sign_in_sign_ups` limit, `supabase/config.toml` — a second, independent layer in front of it, not a stricter one) |
| `aiByUser`         | 30 / hour      | Signed-in caller | `POST /api/{alerts,investigations,indicators}/:id/ai` (a real, metered cost per call)                                                                                                           |
| `alertWriteByUser` | 60 / minute    | Signed-in caller | `POST /api/alerts` (every insert also runs the `alerts_dedup_and_rules` trigger)                                                                                                                |
| `ingestByKey`      | 120 / minute   | The API key's id | `POST /api/ingest/wazuh` and `/api/ingest/splunk` (generous — a real sensor delivers steadily; the cap catches a misbehaving or compromised key)                                                |

None of these are admin-configurable, the same narrowing decision Phase 10 made for the dedup window: a
portfolio deployment on free-tier quotas needs a floor, not a dial.

## Indicators and search

Indicators (IOCs) are the first domain data. Records are returned as the database has them
(`snake_case`, `origin`, `tags`), and every one carries `origin` (`demo`, `local` or `external`).

`GET /api/indicators` accepts (all optional):

| Parameter                                         | Meaning                                                                                                                                                                                                                                             |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `q`                                               | Search text, up to 200 characters. Every word (at most 8) must match the value, description, source or a tag, ignoring case. `%` and `_` are literal.                                                                                               |
| `type`, `status`, `verdict`, `severity`, `origin` | Exact filters, enum values as in the database. A blank value means no filter.                                                                                                                                                                       |
| `tag`                                             | Only indicators carrying this tag (case-insensitive).                                                                                                                                                                                               |
| `sort`, `order`                                   | `last_seen` (default), `first_seen`, `created_at`, `updated_at`, `value`, `type`, `severity`, `verdict`, `status`, `confidence`; `desc` (default) or `asc`. Severity and verdict sort by rank (critical first when descending), not alphabetically. |
| `page`, `page_size`                               | As for every list. A page past the end is an empty page with the real `total`, not an error.                                                                                                                                                        |

Writes:

- `POST /api/indicators` needs `indicators:write`. Body: `type`, `value`, and optionally `severity`,
  `verdict`, `status`, `confidence` (0-100), `source`, `description`, `first_seen`, `last_seen` (ISO
  timestamps) and `tags` (at most 20 names, up to 50 characters, duplicates ignoring case dropped).
  The value is trimmed and stored canonically (hosts, hashes and emails in lower case, CVE ids in upper
  case) and checked per type with the same rules as the database. **The body is strict: `origin`,
  `created_by` and ids are refused (422).** New records are always `local`; the database enforces this
  too, and nobody can relabel a record afterwards. A duplicate (same type and value ignoring case) is
  `409` with `error.details.existing_id`.
- `PATCH /api/indicators/:id` needs `indicators:write`. Any of `severity`, `verdict`, `status`,
  `confidence`, `source`, `description` (`""` or `null` clears it), `first_seen`, `last_seen`, `tags`
  (replaces the whole set atomically). `type` and `value` cannot change; an empty body is `422`.
- `DELETE /api/indicators/:id` needs `indicators:delete` (admins). Tags and relationships go with it.
- `GET /api/indicators/:id` returns the record with `tags`,
  `relationships` (each with `direction` and the other indicator) and `created_by_name`. A malformed or
  unknown id is `404`.

Create, update and delete are audited (`indicator.created`, `indicator.updated`, `indicator.deleted`) with the
type and value in `metadata`.

`GET /api/search?q=<2-200 characters>&limit=<1-10>` (any signed-in user) searches every record type the
caller may read and returns `{ query, groups: [{ kind, label, total, hits: [{ id, title, subtitle, href,
origin }] }] }`. Indicators, vulnerabilities, alerts, investigations and
ATT&CK techniques are searchable (each source is skipped for a caller without its read permission, and searches
with the same query schema and repository as its list page; a technique has `origin: null`, it is public
reference data); new record types register in `src/lib/search/service.ts` once their pages exist. When the text is, by structure alone, an IP address,
domain, URL or file hash (and the caller has `indicators:read`), a first group `lookup` offers the
matching lookup page (`origin` is `null`: it is an action, not a record, and it claims nothing about the
value).

## Intelligence lookups

`GET /api/intel/:kind?value=<subject>` needs `indicators:read`. `kind` is `ip`, `domain`, `url` or `hash`
(anything else is `404`). The value is trimmed, validated for that kind and canonicalized (hosts and hashes
in lower case, URLs as typed, an MD5, SHA-1 or SHA-256 recognized by length); a malformed value is a `422`
naming `value`.

```json
{
  "kind": "ip",
  "value": "198.51.100.23",
  "indicator_type": "ipv4",
  "results": [
    {
      "provider": { "id": "demo", "name": "Demo dataset", "origin": "demo" },
      "profile": { "kind": "ip", "...": "..." }
    }
  ],
  "attempts": [
    { "provider": { "id": "demo", "name": "Demo dataset", "origin": "demo" }, "status": "ok" }
  ],
  "live_providers": [],
  "live_allowed": false,
  "fallback": false,
  "local": {
    "indicator": null,
    "related": [],
    "alerts": [],
    "events": [],
    "investigations": [],
    "timeline": []
  }
}
```

- **`results`**: one entry per provider that delivered, each with its own `provider.origin` (`demo` or
  `external`) and `profile.retrieved_at`. Answers of different providers are never blended. The profile
  depends on the kind: `ip` (version, network, ASN, organization, ISP, usage, country, region, city,
  hostnames, open ports, related domains, abuse reports), `domain` (registrar, dates, nameservers, DNS
  records, related IPs, categories), `url` (host, final URL, redirect chain, HTTP status, title) and `hash`
  (all three digests, malware families, file name, type, size); every profile also has `reputation`
  (`verdict`, `confidence` when the provider states one, `summary`), `detections` (engine counts),
  `findings` (engines that flagged it), `tags` and `last_analysed_at`.
- **`attempts`**: what happened with every provider that was considered. `status` is `ok`, `not_found`,
  `skipped` (`reason`: `not_permitted`, `not_public`, `has_credentials`) or `failed` (`reason`: `auth`,
  `rate_limited`, `timeout`, `unavailable`, `bad_response`, plus `retry_after_seconds`).
- **`fallback`**: `true` when live providers are connected but none delivered, so demo data is shown.
  Demo data is only used when no live provider produced an answer.
- **`local`**: what the workspace knows: the tracked indicator (`IndicatorDetail`, with relationships and
  its relationships), other indicators that mention the subject, its alerts, events and
  investigations, and a merged `timeline` (newest first, at most 25 entries).

Rules that hold for every lookup:

- **The demo provider is the default** and needs no key. It knows a small fictional scenario (the seeded
  indicators) and a few harmless well-known subjects; for anything else it answers `not_found`.
- **Live providers are optional.** VirusTotal (`VIRUSTOTAL_API_KEY`: IP, domain, URL, hash) and AbuseIPDB
  (`ABUSEIPDB_API_KEY`: IP) are asked only when their key is set on the server, **only for callers with
  `indicators:write`** (SOC L2 analysts and administrators, so a self-registered viewer cannot spend the quota),
  all in parallel under one 8-second deadline. `live_providers` lists the ones that could answer this kind.
- **Nothing private leaves the workspace.** Private, loopback, link-local, documentation and other reserved
  addresses, reserved names (`.example`, `.test`, `.local`, `example.com`, ...) and URLs that carry a user
  name or password are never sent to a live provider (`skipped` / `not_public`, `has_credentials`).
- **Nothing is fetched, uploaded or scanned.** Providers are asked what they already know; a URL is never
  opened and a file is never uploaded. Every outbound request goes to the provider's own fixed HTTPS
  address (no redirects, size cap, deadline), with the key in a header; a lookup value never decides the host.
- **Verdicts are conservative.** Engine counts: three or more `malicious` is `malicious`, one or two (or any
  `suspicious`) is `suspicious`, none flagged is `unknown` (never `benign`). AbuseIPDB's score: 75 and above
  `malicious`, 25 and above `suspicious`, allow-listed `benign`, otherwise `unknown`.
- **Audit:** a lookup that contacts a live provider writes one `intel.lookup` entry (kind, the value, which
  providers and how each answered; a URL is recorded without its query string). Demo lookups write nothing.

## Vulnerabilities

Records live in the database (demo seed, local, or imported from a provider); the list and detail read them
with the caller's own client, so row level security decides what is visible.

`GET /api/vulnerabilities` accepts (all optional):

| Parameter                              | Meaning                                                                                                                                                                                                            |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `q`                                    | Search text, up to 200 characters. Every word (at most 8) must match the CVE id, title, description, or an affected vendor or product, ignoring case. `%` and `_` are literal.                                     |
| `severity`, `exploit_status`, `origin` | Exact filters, enum values as in the database. A blank value means no filter.                                                                                                                                      |
| `min_cvss`                             | Only records scored at or above this number (0-10).                                                                                                                                                                |
| `sort`, `order`                        | `published_at` (default), `modified_at`, `cvss_score`, `severity`, `cve_id`; `desc` (default) or `asc`. Severity sorts by rank (critical first when descending). Records without a score or date always sort last. |
| `page`, `page_size`                    | As for every list; a page past the end is an empty page with the real `total`.                                                                                                                                     |

- `GET /api/vulnerabilities/:cve` returns the record with `affected_products` (vendor, product, affected
  versions, fixed version) and `indicator` (the workspace indicator that tracks the CVE, or `null`). The id
  may be in any case; an unknown or malformed id is `404`.
- `GET /api/vulnerabilities/stats` returns `{ total, exploited, by_severity: [{ severity, total, exploited }] }`
  with every severity, most severe first.
- `POST /api/vulnerabilities/import  { cve_id }` needs `vulnerabilities:write` (administrators). It asks the
  connected provider (NVD, when `NVD_API_KEY` is set) and records the CVE as **external** data, or refreshes the
  external record already there: `201` when new, `200` when refreshed. `503` when no provider is connected or
  the provider could not answer (`NVD: The provider rejected the API key.`), `429` with `Retry-After` when it
  rate limits, `404` when it has no such CVE, `409` when a demo or local record with that id exists (it is
  never replaced), `422` for a malformed id or extra fields. The write goes through the service-only
  database function `import_external_vulnerability()`; clients cannot create external or demo records, and
  nobody can relabel one. Imports are audited as `vulnerability.imported`.
- The NVD adapter maps the highest available CVSS version (4.0, 3.1, 3.0, 2.0) to a score, vector and
  severity (a CVE NVD has not scored yet is `info` with no score, never a guess); `exploited_in_wild` only
  when CISA lists it, `poc_available` only when a reference is tagged `Exploit`; references are kept only
  when they are http(s) links.

## Alerts

Alerts are detections that need a decision. Every record carries `origin`; the demo seed has 15, alerts made
through the API are `local` with source `manual`, and live alerts will arrive through ingestion (Phase 6b) as
`external`. The database refuses a client-chosen origin and any relabelling (`alerts_protect_origin`).

`GET /api/alerts` accepts (all optional):

| Parameter                      | Meaning                                                                                                                                              |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `q`                            | Every word (at most 8) must match the title, description, source or the value of the linked indicator, ignoring case. `%` and `_` are literal.       |
| `status`, `severity`, `origin` | Exact filters (`new acknowledged investigating resolved false_positive`, ...). A blank value means no filter.                                        |
| `source`                       | Exact source (for example `demo-edr`, `manual`).                                                                                                     |
| `assignee`                     | `me`, `none` (nobody has picked it up) or a user id.                                                                                                 |
| `duplicates`                   | Unset (default): hide a duplicate alert from the list. `show`: include it alongside its primary.                                                     |
| `sort`, `order`                | `created_at` (default), `updated_at`, `severity` (by rank, critical first when descending), `status`; `desc` (default) or `asc`. Ties break on `id`. |
| `page`, `page_size`            | As for every list; a page past the end is an empty page with the real `total`.                                                                       |

- `GET /api/alerts/stats` returns `{ total, unassigned, by_status: [{ status, total, unassigned }] }`, every
  status in lifecycle order; a duplicate alert is excluded, the same as from the default list.
- `GET /api/alerts/:id` returns the alert with `indicator`, `event` (with its raw `payload`), `assignee`,
  `investigations`, `created_by_name`, `matched_rule` (`{ id, name } | null`, see "Detection rules and alert
  deduplication") and `duplicates` (other alerts linked to this one, empty unless this is a primary with
  some). A malformed or unknown id is `404`.
- `POST /api/alerts  { title, description?, severity?, indicator_id? }` needs `alerts:write`. The body is
  strict: `origin`, `source`, `status` and ownership are refused (`422`). Blank text becomes `null`.
- `PATCH /api/alerts/:id  { status?, assigned_to? }` needs `alerts:write`; an empty or wider body is `422`.
  **The lifecycle is a state machine** (`src/lib/alerts/workflow.ts`): `new` can become `acknowledged`,
  `investigating`, `resolved` or `false_positive`; `acknowledged` can become `investigating`, `resolved` or
  `false_positive`; `investigating` can become `resolved` or `false_positive`; a closed alert can only be
  reopened into `investigating`, never back to `new`. Anything else is `409`, and so is a change somebody
  else made in the meantime (the update only applies while the alert is still in the status the caller saw).
  The server works out the timestamps: `acknowledged_at` is set when an alert first leaves `new` and kept,
  `resolved_at` is set exactly when it is closed and cleared on reopening, and an unassigned alert that is
  taken out of `new` is assigned to the caller. `assigned_to` is a user id, `me` or `null`; only active people
  who hold `alerts:write` can be assigned an alert (`422` otherwise).
- `DELETE /api/alerts/:id` needs `alerts:delete` (administrators).

Audited: `alert.created`, `alert.status_changed` (from, to), `alert.assigned`, `alert.deleted`. Attaching an
alert to an investigation that moves it to `investigating` writes the same `alert.status_changed` entry with
`reason: "attached to an investigation"`.

## Investigations

`GET /api/investigations` accepts `q` (every word must match the title, description, a tag or the value of an
attached indicator), `status`, `priority`, `origin`, `tag`, `analyst` (`me`, `none` or a user id), `sort`
(`updated_at` default, `created_at`, `priority` by rank, `status`, `title`), `order`, `page`, `page_size`. Rows
carry `analyst`, `tags`, `indicator_count` and `alert_count`. `GET /api/investigations/stats` returns the count
per status (`open investigating contained resolved closed`).

- `POST /api/investigations  { title, description?, priority?, analyst_id?, tags?, indicator_ids?, alert_ids? }`
  needs `investigations:write`. An investigation always starts `open` and `local`; the analyst defaults to the
  caller (`null` leaves it unassigned, `me` means the caller). Every attached id must exist (`422` naming the
  field, before anything is created), at most 50 indicators and 20 alerts at once. Attached alerts that are
  `new` or `acknowledged` move to `investigating` through the same lifecycle rules as any other change.
- `GET /api/investigations/:id` returns the record with `analyst`, `tags`, `indicators` and `alerts` (each
  with who attached it and when), `notes` (ordinary notes and the system history together, oldest first),
  `evidence` and a merged `timeline` (newest first).
- `PATCH /api/investigations/:id` needs `investigations:write`: any of `title`, `description`, `status`,
  `priority`, `analyst_id`, `tags` (replaces the set atomically). `closed_at` is worked out by the server
  (stamped when the status becomes `closed`, cleared when it leaves it) and is not the client's to set. A
  change of status, priority or analyst leaves a line in the history (a `system` note, written with the
  service role; failing to write it never undoes the change).
- `POST /api/investigations/:id/indicators  { indicator_id }` and `.../alerts  { alert_id }` attach (`201`,
  `409` when already attached); `DELETE .../indicators/:indicatorId` and `.../alerts/:alertId` detach (`404`
  when not attached). Detaching removes only the link.
- `POST .../notes  { body }` adds a note (`201`); `PATCH .../notes/:noteId` edits it (only its author);
  `DELETE .../notes/:noteId` removes it (its author, or an administrator). **System notes (the status history)
  cannot be created, edited or deleted by anyone through the API**, and row level security says the same.
- `POST .../evidence  { title, location, description? }` adds an evidence _reference_ (a link, a file hash, a
  ticket number or a path; nothing is uploaded or fetched); `DELETE .../evidence/:evidenceId` removes it.
- `DELETE /api/investigations/:id` needs `investigations:delete` (administrators). Notes, evidence, tags and
  links go with it; the attached indicators and alerts stay.

Every write returns the investigation (or its detail) and is audited: `investigation.created|updated|deleted`,
`investigation.link_added|link_removed` (kind and value), `investigation.note_added|note_updated|note_deleted`,
`investigation.evidence_added|evidence_removed`. Note and evidence text is never copied into the audit trail
(only ids and the evidence title).

## MITRE ATT&CK

There are no threat actor, campaign or malware records in ArcRadar (they were removed on 2026-09-30: a catalog of who might be behind attacks in general says nothing about your own machines). What remains is the ATT&CK **technique catalog** as reference data, and what your own alerts say about it. Needs `threat_intel:read`.

- `GET /api/mitre[?observed=1]` returns the matrix: `{ tactics: [{ name, techniques: [...], observed_techniques }], summary: { observed_techniques, total_techniques } }`. Columns run in the order of an attack (Reconnaissance to Impact); a technique belonging to several tactics appears in each. Each technique has `{ id, name, url, observed, subtechniques }`; `observed` is `{ alert_count, max_severity, last_seen }` when at least one alert (a duplicate does not count) names the technique, and `null` otherwise. A sub-technique (`T1110.003`) also counts for its parent (`T1110`), once per alert. `observed=1` keeps only what was observed (a parent stays when a sub-technique was); anything else for `observed` is `422`.
- `GET /api/mitre/:id` (`T1566` or `T1078.001`, any case) returns the technique with `description`, `tactics`, `url`, `parent_id`, `subtechniques`, `observed`, the newest 25 `alerts` that name it (a parent includes its sub-techniques' alerts; only alerts the caller may read) and `alert_total`. A malformed or unknown id is `404`.
- `GET /api/alerts?technique=T1110` lists the alerts that name a technique (a parent also matches its sub-techniques); a malformed id is `422`. This is what a click on a highlighted technique of the matrix opens.
- The technique catalog is read-only through the API; it is loaded with `npm run import:mitre` (the seed only carries a few techniques). `mitre_observed_techniques()` is the SQL function behind the highlighting, with the caller's own row level security.

## Indicator relationships

- `POST /api/indicators/:id/relationships  { target_id, relationship }` needs `indicators:write`: this
  indicator (the source) `resolves_to`, `communicates_with`, `downloads`, `hosted_on` or `related_to` the
  target. The same pair and kind twice is `409`; an indicator related to itself, a target that does not exist
  or an unknown kind is `422`. Returns the indicator (`201`). `DELETE
/api/indicators/:id/relationships/:relationshipId` removes one that involves the indicator as source or
  target (`404` otherwise). Audited as `indicator.relationship_added` and `indicator.relationship_removed`.

## Telemetry ingestion and API keys

Machines (a Wazuh Manager, a script) authenticate with an **API key**, not a session. Setup for a Manager:
`docs/WAZUH_INTEGRATION.md`; design: `docs/TELEMETRY_ARCHITECTURE.md`.

**API keys** (`src/lib/api-keys/`). `POST /api/api-keys  { name, scopes, expires_in_days? }` returns
`{ key, api_key }` with `201`; `key` is `arc_` + 43 URL-safe characters, shown **once** (ArcRadar keeps only its
SHA-256 hash and an 8-character prefix for recognition). `scopes` are chosen from `ingest:wazuh`, which needs the
`events:write` permission (administrators only, `403` for anyone else); `expires_in_days` is 1 to 365
(default 365) or `null` for a key that never expires. A person can hold 10 usable keys (`409` after that). `GET`
lists keys with a `status` of `active`, `expired` or `revoked`, `last_used_at` (refreshed at most once a
minute) and the prefix. Audited as `api_key.created` and `api_key.revoked` (name, scopes, prefix, expiry, never
the key).

**Using a key.** Requests carry `Authorization: Bearer arc_...`. Every request re-checks the key: well formed,
known, not revoked, not expired, owned by an **active** account that **still holds** the permission behind the
scope, and carrying the scope. Every reason a key is unusable is the same `401` (with `WWW-Authenticate`), so
a caller learns nothing about which keys exist; a valid key without the scope is `403`.

**`POST /api/ingest/wazuh  { "alerts": [ <Wazuh alert JSON>, ... ] }`** takes 1 to 100 alerts and at most
1 MiB (`413`/`415`/`400`/`422` for an oversized, non-JSON, malformed or wrongly shaped body). It uses the
`ingestRoute({ scope })` wrapper (third to `publicRoute` and `protectedRoute`): no cookies, so no same-origin
check, and no user-scoped Supabase client. The request is normalized by the Wazuh `TelemetrySource` adapter
(`src/lib/telemetry/wazuh.ts`) and stored in **one transaction** by `ingest_telemetry()`, a `security definer`
function that only the service role can execute. The answer is

```json
{
  "received": 3,
  "events_created": 3,
  "alerts_created": 2,
  "duplicates": 0,
  "assets_created": 1,
  "indicators_created": 2,
  "rejected": [{ "index": 1, "reason": "..." }]
}
```

- Every usable alert becomes an **event**; a rule level of 7 or more (`ALERT_MIN_LEVEL`) also becomes an
  **alert** with `status = new`; lower levels stay events and create no indicators.
- **Idempotent.** The identity of an alert is `<manager name>:<alert id>`; one already received counts as a
  `duplicate` and changes nothing (a unique index on `(source, source_event_id)` for external rows), so a
  retry or a Manager that resends is harmless.
- **An alert that cannot be used is rejected on its own** (listed in `rejected` with its index and a reason);
  it never fails the request. A database refusal of the whole batch (a malformed technique id, say) is a
  `422` and nothing is stored.
- The **agent becomes an asset** (`assets`, unique per source and agent id; `last_seen` never moves back). The
  ATT&CK ids in the rule are kept (at most 20). Up to five **indicators** are taken from a level-7+ alert
  (public or documentation addresses, file hashes, domains, URLs), recorded `external` with the verdict
  `unknown`; an indicator somebody already tracks is linked and never changed. A bounded copy of the raw alert
  (16 KiB) is kept with the event.
- Everything ingested is `origin = external` and `source = wazuh`. Clients cannot create such rows, and the
  function is not callable with a user's token.
- Audited once per request as `ingest.batch` (key name and prefix, owner, counts; never the alerts).

**Reading it back.** `GET /api/telemetry/sources` returns one card per source with `status`: `receiving`
(something arrived within 15 minutes), `quiet`, `never` (a connector that has not delivered yet) or `demo`
(sample data, never a live connection). ArcRadar cannot see a sensor, so it never says "connected".
`GET /api/events` and `GET /api/assets` are ordinary paginated lists behind `events:read`; the Telemetry page
uses them, with its state in the address like the other lists. Alerts gained `asset` and `technique_ids`, and
`GET /api/alerts?q=` also matches the asset's name or address.

## Dashboard

`GET /api/dashboard?days&severity` is what the Overview page renders (the page calls the same service
directly; the route exists for API consumers and `api:smoke`). `days` (1-90, default 14) bounds the activity
series and the "recent" panels; `severity`, when set, narrows the recent alerts and indicators panels. The
headline counts (`counts`) are always the workspace's real, unfiltered totals — a dashboard that hid the true
number to match a filter would be misleading. Available to every signed-in role (a viewer already holds every
`*:read` permission it touches). Answers:

```json
{
  "counts": {
    "indicators_total": 41,
    "indicators_malicious": 23,
    "alerts_active": 10,
    "...": "..."
  },
  "severity_distribution": [{ "severity": "critical", "total": 4 }],
  "ioc_distribution": [{ "type": "ipv4", "total": 10 }],
  "verdict_distribution": [{ "verdict": "malicious", "total": 23 }],
  "activity": [{ "day": "2026-09-14", "alerts": 2, "events": 3 }],
  "top_techniques": [
    { "id": "T1110", "name": "Brute Force", "alert_count": 2, "max_severity": "high" }
  ],
  "top_malicious_indicators": ["..."],
  "recent_indicators": ["..."],
  "recent_alerts": ["..."],
  "recent_investigations": ["..."]
}
```

## Reports

A report is a **snapshot**: `POST /api/reports` computes it from the workspace's current data once, at
creation time, and stores it (`content`) alongside what was asked for (`parameters`). It never changes
afterwards; generate a new one to refresh it. `type` picks the shape and what else the body needs:

| `type`            | Extra field        | What `content` holds                                                                     |
| ----------------- | ------------------ | ---------------------------------------------------------------------------------------- |
| `indicators`      | —                  | Total, counts by type and verdict, the most recently seen malicious indicators           |
| `alerts`          | —                  | Total, counts by status and severity, the alerts still open                              |
| `vulnerabilities` | —                  | Total, counts by severity (with how many are exploited), CVEs exploited in the wild      |
| `investigation`   | `investigation_id` | The investigation's status, priority, analyst, linked indicators/alerts, notes, evidence |

`title` is optional (a reasonable one is generated, for example "Alert summary — 2026-09-27" or
"Investigation report: Harbor Lights C2 infrastructure"). Reports are always `origin = local`; the workspace
types (`indicators`/`alerts`/`vulnerabilities`) summarize the current state, like the dashboard, and take no
date range. Reports have their own search (`search_reports`, title only, same ANDed-terms/literal-wildcards
shape as every other `search_*` function). Audited as `report.created` and `report.deleted` (title and type
only, never the content).

## Integrations and users

**`GET /api/integrations`** lists the provider catalog (`demo`, the live intel/vulnerability providers, and
`wazuh`) with `capabilities`, whether a server-side key is `configured` (never the key itself), and whether an
administrator has `enabled` it. `enabled` is a second, independent gate on top of the key: a live lookup
(`GET /api/intel/:kind`) or a vulnerability import (`POST /api/vulnerabilities/import`) skips a provider an
administrator has disabled, even while its key is set. **`PATCH /api/integrations/:provider { enabled }`**
needs `integrations:manage` (admins); the demo provider can never be turned off (`409`); an unknown provider is
`404`. Audited as `integration.updated` (`enabled`, never a key).

**`GET /api/users`** (admin) reads `auth.users` through the service role (the only way to see another
person's email) joined with each profile's role and active flag. **`PATCH /api/users/:id` `{ role_name?,
is_active? }`** changes either or both; it refuses to act on the caller's own account (`409`, avoids an
accidental self-lockout) and refuses to leave the workspace with no active administrator (`409`; there is no
separate "root" account to recover with). Audited as `user.role_changed` (`from`, `to`) and
`user.activated`/`user.deactivated`, only when the value actually changed.

**`POST /api/users` `{ email, password, display_name, role_name }`** (admin, `users:manage`) lets an
administrator make an account for a teammate. It is created through Supabase Auth's admin API with the email
already confirmed (the administrator vouches for it, so nothing is mailed), then activated with the chosen
role, which also counts as its approval. The password must meet the sign-up policy (`422` on the `password`
field otherwise); a role is required and unknown fields are refused (`422`); an email that already has an
account is `409`. If the role cannot be given, the half-made sign-in is deleted again, so no account is left
that nobody approved. Answers `201` with the same shape as a row of `GET /api/users`. Limited to 20 a
caller per 10 minutes (`userCreateByUser`). Audited as `user.created` with the role, never the password.

## Automatic data: lookups that record themselves, public feeds

**Lookups record themselves.** When `GET /api/intel/:kind` is answered by at least one _live_ provider (never
the demo one) for a caller with `indicators:write`, the subject is stored as an `external` indicator and the
response says `recorded: "created" | "updated" | "untouched" | null` (`untouched`: the workspace already
tracks it as its own, `null`: nothing real to record). The verdict is the worst any provider reached; an
existing `local`/`demo` indicator is never changed and a verdict only moves up. Audited as
`indicator.recorded_from_lookup`. Providers today: VirusTotal, AbuseIPDB, AlienVault OTX (`OTX_API_KEY`) and
Shodan InternetDB (`SHODAN_INTERNETDB=true`, no key, IPs only).

**`POST /api/feeds/import { groups? }`** (`integrations:manage`; `groups`: `abusech` and/or `cisa_kev`, both by
default; rate limited, `feedImportByUser`). Downloads the public feeds now and answers one entry per feed:
`{ feed, group, status: ok | failed | disabled, fetched, created, updated, untouched, skipped, error? }`. A
group an administrator paused on the Integrations page is `disabled`; one feed failing does not stop the
others (`error` is a short, safe reason). Audited as `feeds.imported`. Nothing runs on a timer: feeds are imported only when an administrator presses Import now.

**Splunk ingestion.** `POST /api/ingest/splunk  { "alerts": [ { sid, search_name, result, results_link?, server_host?, configuration? }, ... ] }`
takes 1 to 100 items, authenticated by an API key with the `ingest:splunk` scope (it needs the same permission,
`events:write`, so administrators issue it; a Splunk key does not open the Wazuh endpoint, `403`). Each item is one
result of an ArcRadar-written saved search that triggered. `sid`, `search_name`, `results_link` and `result` are
what Splunk's own webhook action sends; `configuration` carries the saved search's parameters
(`rule_key`, `name`, `severity` low to critical, `mitre` as a comma list). It goes through the same `ingestRoute`,
`ingest_telemetry('splunk', ...)` and rate limit as Wazuh: every item becomes an event and an alert (a Splunk
alert is already a triggered one), the `host` field becomes an asset, public IPs, hashes and URLs in the result
become indicators (verdict unknown), and the new indicators are researched afterwards exactly as for Wazuh. The event
id is `<search_name>:<sid>:<digest of the result row>`, so a retry is a duplicate and two rows of one search run
are two events; identical alerts within an hour link as duplicates through the usual deduplication trigger. Without
a parsable `_time` the time of receipt is used. An unusable item is listed in `rejected`. Fictional samples:
`npm run ingest:sample -- --siem splunk`.

**Splunk field catalog.** `POST /api/ingest/splunk/catalog` (key scope `ingest:splunk`, rate limit `ingestByKey`) lets the Splunk host report which fields its data really has, so the rule form can offer them and the AI can be told them. The body is `{ sources: [ { index, sourcetype, window_hours, events_sampled, fields: [ { name, count, distinct?, values? } ] } ] }` (1 to 50 sources, up to 500 fields each, at most 20 example values per field). It is stored by `sync_field_catalog()` (service role only): each reported source replaces its earlier report in one transaction, a field whose name is not a plain Splunk field name is skipped (not fatal), a count is capped at the sample size, example values are cut to five of at most 100 characters. Answers `{ sources, fields }`; audited as `ingest.catalog` (counts, never the values). The values come from real logs, so `GET /api/siem-rules/splunk/fields` (administrators, `rules:manage`) is the only way to read them. The rule form (a datalist of indexes, sourcetypes, fields with how often they appear, and example values per condition, plus a warning for a field Splunk has not seen) and the AI draft (`generateSiemRule` adds the catalog summary to the prompt: only real index, sourcetype and field names) use it.

**Rule mode and backtests.** A rule is pushed in `live` mode (the default) or in `test` mode (`POST .../push?mode=test`). A test-mode file is loaded by the SIEM but has `enableSched = 0` and no action, so it never runs on a schedule and never alerts; pushing again with `?mode=live` replaces the file with the live version (`Go live`). The rule's `mode` is the mode of the last push. The SIEM host then runs the rule's search over the last 24 hours and 7 days and reports it with `POST /api/ingest/splunk/backtests` (key scope `ingest:splunk`, rate limit `ingestByKey`): `kind` is `threshold` (matches counts the time buckets and groups over the limit, in fixed slices of the rule's window) or `events` (matches counts events), `scanned` is how many events the base search covers, `sample` up to five examples, `search_sha256` the digest of the search that was run. A rule's `backtests` (in `GET /api/siem-rules/splunk`) carry `stale: true` when that digest is not the digest of the rule's current search, so a result for an older version is flagged. Stored by `sync_rule_backtests()` (service role only), one row per rule and window, replaced by a later report; audited as `ingest.backtest` (counts only); deleting a rule deletes its backtests.

**Withdrawing a rule.** `POST /api/siem-rules/:siem/:id/reject` on a rule that is on GitHub (pushed, in either mode) deletes its file from the repository first (`DELETE` on GitHub's contents API; a file that is already gone is not an error), then marks the rule rejected and forgets its `github_path`. If GitHub is not configured (`503`) or fails (`503`, `409`, `429`) nothing changes. The audit entry `siem_rule.rejected` records `withdrawn`, the path, the commit and the repository. The SIEM host drops the rule the next time it pulls: it is woken at once, because the revision it waits on also moves on a withdrawal (`siem_rules_revision()` is the latest of `pushed_at` and `rejected_at` over rules that were ever pushed). A withdrawn rule can be edited and pushed again.

**The wake-up.** So that a rule pushed in ArcRadar reaches Splunk and is tested within seconds without any timer on the SIEM side, the Splunk host keeps one request open: `GET /api/ingest/splunk/wake?since=<revision>&wait=25` (key scope `ingest:splunk`, rate limit `ingestByKey`). The _revision_ is the time of the latest rule push (`siem_rules_revision()`, service role only; a rule's `pushed_at` changes on every push, in either mode, and a draft does not move it). ArcRadar checks it once a second for up to `wait` seconds (0 to 25) and answers `{ revision, changed }` the moment it differs from `since`, or after the wait with `changed: false`; without `since` it answers at once with the current revision. The host then pulls and tests the rules and asks again. Only the host calls ArcRadar: no port of the SIEM is opened, and the revision carries no rule.

**Research on arrival.** When a Wazuh delivery (`POST /api/ingest/wazuh`) creates alerts, the new indicators in them (public IPs, domains, URLs, file hashes) are researched at the live providers that are set up and switched on, right after the response is sent (`after()`, so the sender never waits): the worst verdict any provider reached, a confidence and a summary are recorded on the indicator (`researched_at` says when). At most 4 indicators per delivery (VirusTotal's free plan allows 4 requests a minute), each only once (`researched_at` is null until then; providers that all failed leave it null so a later delivery retries; providers that all answered "unknown to me" still count as researched), never a private or reserved address, never an indicator somebody tracks as their own (local or demo), and never at all when no provider is configured. Audited as `indicator.researched` (`trigger: ingest`, the providers' outcomes, never the values).

MITRE ATT&CK is loaded with the `npm run import:mitre` script (see `docs/LOCAL_DEVELOPMENT.md`), not an endpoint.

## AI analysis

AI is a third provider family next to intel lookups and integrations, added in Phase 8
(`docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md`): a language-model provider that turns an alert an analyst can
already read into one structured, labelled analysis. Nothing runs on its own — every row answers one explicit
click — and an answer is stored immutably (like a report): re-running a kind adds a new row rather than
changing an old one.

**`GET /api/ai/settings`** (`ai:use`, so analysts see this too, not only admins) lists every AI-capable
provider (`groq`, `openai`, `anthropic`, `deepseek`, `ollama`) with whether it is `configured` (a server-side
key, or for `ollama` its base URL, is set) and `enabled` (an administrator has not paused it on the
Integrations page), plus which one (if any) is `active` right now and its `ready` flag (`active_provider` is
set **and** that provider is both configured and enabled). **`PATCH /api/ai/settings` `{ active_provider,
active_model }`** (`ai:manage`, admin) chooses the active provider and an optional free-text model name (or
clears both with `null`); the provider must already be configured and enabled (`409` otherwise), and a model
without a provider is rejected (`422`). Audited as `ai.settings_updated`.

**`GET /api/{alerts,investigations,indicators}/:id/ai`** (the matching `*:read` — anyone who can see the
record sees analyses already generated for it) returns `{ latest, history }`: `latest` is one row per `kind`
that has ever run for that record, `history` is every run, newest first. **`POST .../ai` `{ kind }`** (`ai:use`
**and** the matching `*:read`) asks the active provider for one `kind` of analysis, validates its answer
against that kind's schema, stores it and audits it (`ai.analysis_generated`); `422` when `kind` does not
belong to that record type (the database enforces the same pairing); `503 DEPENDENCY_UNAVAILABLE` when no
provider is active and ready, `429` when the provider's own rate limit was hit, `503` again if the provider's
answer fails validation. `kind` is one of:

| `kind`                    | Attaches to   | Shape of `content`                                      | Side effect                                                                  |
| ------------------------- | ------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `threat_summary`          | alert         | `{ summary, key_points[] }`                             | —                                                                            |
| `attack_vector`           | alert         | `{ techniques: [{ id, name, confidence }], narrative }` | —                                                                            |
| `severity_validation`     | alert         | `{ agrees, suggested_severity, reasoning }`             | —                                                                            |
| `response_actions`        | alert         | `{ actions: [{ title, why, urgency }] }`                | seeds a catalog entry + a `recommended` log row per action; see below        |
| `false_positive_score`    | alert         | `{ score, reasoning }`                                  | `score` cached on `alerts.ai_fp_score` for sorting                           |
| `investigation_checklist` | investigation | `{ items: string[] }`                                   | seeds trackable `investigation_checklist_items` rows                         |
| `verdict_recommendation`  | indicator     | `{ verdict, confidence, reasoning }`                    | none — applying it is a normal `PATCH /api/indicators/:id` the analyst makes |

A stored analysis always renders in a card labelled "AI-generated — analyst-assisted", next to the record's
real fields, never in place of them: it is a recommendation for a human to review, never an instruction that
gets executed.

## Investigation checklists

`investigation_checklist_items` is a plain, per-investigation to-do list: an AI `investigation_checklist`
analysis seeds a batch of items (`source: "ai"`), and an analyst can add, check off or remove items by hand
(`source: "analyst"`) the same way. **`GET /api/investigations/:id/checklist`** (`investigations:read`) lists
every item, oldest first. **`POST .../checklist` `{ text }`** (`investigations:write`) adds one; audited as
`investigation.checklist_item_added`. **`PATCH .../checklist/:itemId` `{ done }`** (`investigations:write`)
checks or unchecks it — the server, not the client, stamps who did it and when (`done_by`/`done_at`), and
unchecking clears both; audited as `investigation.checklist_item_updated`. **`DELETE .../checklist/:itemId`**
removes it; audited as `investigation.checklist_item_removed`. Every endpoint returns the item's own
investigation's full, fresh list, so a client never has to guess the resulting state.

## Response orchestration

"Governed, not automated": ArcRadar tracks response actions a person recommends, acknowledges, completes or
skips — it never executes anything itself. `response_actions` is a small, reusable catalog (curated the same
way threat intelligence is: provenance-protected, always `local` from a client) of things like "Isolate the
host"; `response_action_log` is one row per recommendation/execution of a catalog action against a specific
alert. **`GET /api/response-actions`** (`alerts:read`) lists the catalog. **`POST /api/response-actions`
`{ title, description?, category? }`** (`investigations:write`) adds an entry, audited as
`response_action.created`; **`PATCH .../response-actions/:id`** edits one (`response_action.updated`);
**`DELETE .../response-actions/:id`** removes one, refused with `409` while an alert still references it in
its log (`response_action.deleted`).

**`GET /api/alerts/:id/response-actions`** (`alerts:read`) lists everything logged for that alert, AI-seeded or
attached by hand. **`POST .../response-actions` `{ action_id }`** (`alerts:write`) recommends an existing
catalog action (`status: "recommended"`, `source: "analyst"`; an AI `response_actions` analysis does the same
with `source: "ai"`), audited as `response_action.attached`. **`PATCH .../response-actions/:logId`
`{ status, notes? }`** (`alerts:write`) moves it forward through `recommended → acknowledged → completed` or
`→ skipped` (never backwards, the same idea as the alert lifecycle): a move the workflow does not allow is
`409`; moving past `recommended` stamps `performed_by`/`performed_at`; audited as
`response_action.status_changed`. **`DELETE .../response-actions/:logId`** removes a mistaken recommendation.
Only `alert`-attached response actions have a page today; the schema also has `investigation_id`, ready for a
later phase to wire up a case-scoped view.

## Wazuh rules

The other kind of rule (`docs/WAZUH_RULES.md` has the full workflow and setup). `wazuh_rules` rows are
rules that run **inside Wazuh**; ArcRadar stores them as structured fields (level, `if_group`/`if_sid`
parent, 1-10 conditions, MITRE ids) and **renders the XML itself**, so no caller can add an element the
generator does not know (an active response, a command). Conditions are `contains` / `equals` / `regex`
tests on a Wazuh field (`win.`, `data.`, `syscheck.` or `agent.` prefix), all written as PCRE2 patterns;
a regex with lookarounds, back-references or nested repetition is `422`. Ids are 100100-999999 (Wazuh ships
examples at 100001-100002); the server picks the next free one when `id` is omitted.

Optional repetition: `frequency` (2-100) and `timeframe` (seconds, 1-86400) are set together or not at all, `same_fields` (up to 3 Wazuh fields) needs them, and a repeating rule may have `conditions: []` (an ordinary one needs 1-10); the file then uses `if_matched_group`/`if_matched_sid`, `frequency`/`timeframe` attributes and `<same_field>`.

Status: `draft` → `pushed` (committed) or `rejected`. Editing a pushed rule sets `changed_since_push`;
editing a rejected rule restores it to a draft. `push` reads the file's current sha, commits (or updates)
`rules/arcradar_<id>.xml` on the configured branch through the GitHub contents API (`src/lib/github/
contents.ts`: fixed `https://api.github.com` base, encoded path segments, no redirects, deadline and size
cap, token in a header, errors without token or body) and does nothing when the content is identical.
Environment: `GITHUB_TOKEN`, `GITHUB_RULES_REPO` (`owner/name`), `GITHUB_RULES_BRANCH` (default `main`).
Rate limits: `wazuhRuleGenerateByUser` (20/hour), `wazuhRulePushByUser` (30/10 min). `triggers` /
`last_triggered` come from `wazuh_rule_trigger_stats()` (alerts whose description starts with
"Wazuh rule <id> (level"). Audited as `wazuh_rule.created|generated|updated|rejected|pushed|deleted`.

## Detection rules and alert deduplication

Both are Phase 10 (`docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md`) and both happen **inline, in one database
trigger** (`alerts_dedup_and_rules`) fired on every `alerts` insert, so ingestion and a manual
`POST /api/alerts` share the exact same behavior — there is no background worker to run either later.

**Detection rules** are a small, admin-curated catalog. `detection_rules.id` is a client-chosen integer in
100000-999999 (mirroring Wazuh's own custom-rule id space, so the two number ranges never collide).
`conditions` is a fixed, closed grammar — never a filter built from free text — an array of 1-10
`{ field, op, value }` rows, ANDed together:

| `field`        | Allowed `op`     | Matches against                           |
| -------------- | ---------------- | ----------------------------------------- |
| `title`        | `contains`       | the alert's title, case-insensitive       |
| `description`  | `contains`       | the alert's description, case-insensitive |
| `source`       | `eq`, `contains` | the alert's source                        |
| `severity`     | `eq`             | the alert's severity                      |
| `technique_id` | `eq`             | any id in the alert's `technique_ids`     |

A `(field, op)` pair outside this table never matches — the database's `detection_rule_matches()` fails
closed, not open, even on a row inserted directly (bypassing this API's own validation). Enabled rules are
tried in `priority` order (lower first); the first match wins, sets `alerts.matched_rule_id`, and — only if
the rule names a `severity` **higher** than the alert already has — raises it. A rule never lowers a
severity and never adds a tag or forces an alert into existence on its own.

**`GET /api/detection-rules`** (`alerts:read`) lists the catalog, so an analyst can see why a rule fired.
**`POST /api/detection-rules` `{ id, name, description?, conditions, severity?, priority?, enabled? }`**
(`rules:manage`, admin only — unlike the response-action catalog, this is not `investigations:write`)
creates one, always `local`; a duplicate `id` is `409`. **`PATCH .../:id`** edits any field except the id
itself; **`DELETE .../:id`** removes it (any alert it had matched keeps its history, `matched_rule_id` is
simply cleared, `on delete set null`). Audited as `detection_rule.created`/`updated`/`deleted`.

**Deduplication** needs no endpoint of its own: `alerts.fingerprint` (an md5 of the normalized `source` +
title + `asset_id` + `indicator_id`) is computed on every insert, and a new alert whose fingerprint matches
an existing **primary** (`duplicate_of is null`) alert that is **still open** (not `resolved` or
`false_positive`) and was **created within the last 60 minutes** is linked as that primary's duplicate
(`duplicate_of` set, the primary's `duplicate_count` incremented) instead of opening a fresh row. A resolved
primary, or one older than the window, does not attract a new duplicate — a real recurrence opens its own.
`GET /api/alerts` hides a duplicate by default (`?duplicates=show` reveals it); `alert_status_counts()`,
`alert_severity_counts()`, `activity_series()` and the dashboard's own alert counts all exclude it the same
way, since it never sat in anyone's queue as a fresh row. `GET /api/alerts/:id` on a duplicate returns
`duplicate_of` and, via the same object shape used everywhere else, its primary's own detail is one more
`GET` away; on a primary it returns its `duplicates` array directly.

## Provider keys saved from the app

`GET /api/secrets` lists the settings an administrator can save (VirusTotal, AbuseIPDB, OTX, NVD,
Shodan InternetDB switch, Groq, OpenAI, Anthropic, DeepSeek, GitHub token / repository / branch) with
where each comes from (`app`, `server` or `none`); a saved secret is never returned, only its last four
characters. `PUT /api/secrets/:name` `{ value }` saves one (validated per setting) and
`DELETE /api/secrets/:name` removes it. All need `integrations:manage`. Values are encrypted with
AES-256-GCM (key: `SECRETS_ENCRYPTION_KEY`, bound to the setting name) before they reach
`provider_secrets`, a table closed to every client role; `getEffectiveEnv()` (`src/lib/secrets/`) lays
saved values over the server environment and is what every provider registry reads. Without
`SECRETS_ENCRYPTION_KEY`, `PUT` answers `503` and the environment variables keep working. The Ollama
address is deliberately not editable here (SSRF, see `docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md`).

## Adding an endpoint

1. Create `src/app/api/<name>/route.ts` and export handlers built with `publicRoute(...)` or
   `protectedRoute({ permissions: [...] }, ...)` from `src/lib/api/handler.ts`. They handle the same-origin
   check, session + permission guard (denials are audited as `authz.denied`), `no-store`, and error mapping.
   An endpoint for a machine uses `ingestRoute({ scope }, ...)` (`src/lib/api/ingest-route.ts`) instead, and
   `src/proxy.ts` leaves `api/ingest/` alone.
2. Validate input with `parseJsonBody(request, schema)` / `parseQuery(request, schema)` (Zod, `z.strictObject`
   for bodies). Put schemas in `src/lib/validation/` or next to the feature.
3. Call a service (business rules), which calls a repository (queries). Repositories use the caller's client
   (`ctx.auth.supabase`, RLS applies) and wrap results with `unwrap()` / `toApiError()` from
   `src/lib/api/supabase-errors.ts` so database errors become safe 4xx/5xx responses.
4. Throw `apiErrors.*` for expected failures; return `ok(data)`. Anything else becomes a generic `500`.
5. Record security-relevant actions with `writeAuditLog()` (`src/lib/audit/write.ts`) after the action is
   authorized. Add the action name to `src/lib/audit/actions.ts`. Never put secrets in `metadata` (secret-looking
   keys are redacted anyway).
6. New permission keys go in a migration first, then in `src/lib/rbac/permissions.ts`; `tests/rbac.test.ts`
   fails when they drift.

## Verifying against the real stack

`npm run api:smoke` (app running, local Supabase up) runs about 424 end-to-end checks: sessions, RBAC per role,
audit entries, sign-up, disabled accounts, the full password-recovery email flow through Mailpit, the
indicator API (search, filters, sorting, paging, every write rule, audit, global search), the intelligence
lookups (demo provider, canonical values, provenance labels, validation), the vulnerability API (search,
filters, sorting, paging, detail, statistics, import permissions), the alert lifecycle (every allowed and
refused move, timestamps, assignment), the investigation lifecycle (notes, evidence, links, history, closing
and reopening, deletion), curation of threat intelligence by role (links set, cleared and kept, failed link
checks changing nothing), indicator links and relationships, API keys and telemetry ingestion (who may make a
key, every way a key is refused, batches with replay, per-alert rejection, size and type limits, what the
ingested alerts, assets, indicators and events look like to people, expiry, revocation), the dashboard (real
counts, window and severity filters, validation), reports (all five types, generated titles, search, type
filter, cross-role read and delete), integrations (the catalog, who may flip the switch, the demo provider
protected), AI settings and per-alert analysis (read/write permissions, validation, a clean `503` with no
provider configured — no AI provider key exists in this environment, so a live call is never made), response
orchestration and checklists (the catalog, recommending and moving an action through its workflow, a blocked
backwards move, a referenced catalog entry refusing deletion, checklist items added/toggled/removed by hand,
the alert-only AI kinds rejected for an investigation or an indicator), profile updates, and user management on
a throwaway account (self-change and last-admin refused, audited role/activation changes, an immediate
lockout), and the audit entries of all of it. It works through nginx too:
`SMOKE_BASE_URL=http://localhost:8080 npm run api:smoke`. It never contacts a live provider (with
`NVD_API_KEY` set it skips the one check that would).

## Supabase Auth settings a hosted project must match

Configured for the local stack in `supabase/config.toml`; set the same in the Supabase dashboard (Phase 9
documents deployment): password policy (minimum length 10, lower + upper + digits), redirect URLs that allow
`<app url>/**`, email confirmation on, and the sign-up toggle off if the deployment is invite-only.
