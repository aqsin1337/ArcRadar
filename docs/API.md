# ArcRadar API conventions

Every endpoint is a Next.js Route Handler under `src/app/api/`. Domain endpoints (indicators, alerts,
...) arrive in later phases and follow the rules below.

## Envelope and errors

Every JSON response has the same shape (`src/lib/api/response.ts`):

```json
{ "success": true, "data": { "...": "..." }, "error": null }
{ "success": false, "data": null, "error": { "code": "FORBIDDEN", "message": "...", "details": {} } }
```

Every response carries `Cache-Control: no-store` and an `x-request-id` header (also written to the server
log for unexpected errors). Field names in JSON are `snake_case`, matching the database.

| Status | `error.code`                                           | Meaning                                                    |
| ------ | ------------------------------------------------------ | ---------------------------------------------------------- |
| 400    | `BAD_REQUEST`                                          | Malformed body (empty, invalid JSON or UTF-8)              |
| 401    | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`               | No/invalid session, or wrong email or password             |
| 403    | `FORBIDDEN`, `ACCOUNT_DISABLED`, `EMAIL_NOT_CONFIRMED` | Missing permission, cross-origin request, disabled account |
| 404    | `NOT_FOUND`                                            | Unknown endpoint or record                                 |
| 409    | `CONFLICT`                                             | Unique/foreign-key conflict                                |
| 413    | `PAYLOAD_TOO_LARGE`                                    | JSON body over 64 KB                                       |
| 415    | `UNSUPPORTED_MEDIA_TYPE`                               | Body is not `application/json`                             |
| 422    | `VALIDATION_ERROR`                                     | `details.issues` = `[{ path, message }]`, no echoed values |
| 429    | `RATE_LIMITED`                                         | Supabase Auth limit hit (`Retry-After` when known)         |
| 500    | `INTERNAL_ERROR`                                       | Unexpected; details are only in the server log             |
| 503    | `DEPENDENCY_UNAVAILABLE`                               | Supabase unreachable or the app is not configured          |

Lists return `{ items, pagination: { page, page_size, total, total_pages } }` and accept
`?page=1&page_size=25` (`page_size` max 100).

## Endpoints

| Method | Path                        | Access               | Notes                                                                  |
| ------ | --------------------------- | -------------------- | ---------------------------------------------------------------------- |
| GET    | `/api/health`               | public               | Liveness + Supabase reachability, no config values                     |
| POST   | `/api/auth/login`           | public               | `{ email, password }`; sets session cookies; returns `me`              |
| POST   | `/api/auth/logout`          | public               | Ends the current session; succeeds when already signed out             |
| POST   | `/api/auth/signup`          | public               | `{ email, password, display_name? }`; always `201`, see below          |
| POST   | `/api/auth/forgot-password` | public               | `{ email }`; always `200 { sent: true }`                               |
| POST   | `/api/auth/update-password` | signed in            | `{ password }`; revokes the user's other sessions                      |
| GET    | `/api/auth/me`              | signed in            | `{ user, profile: { display_name, role }, permissions }`               |
| GET    | `/api/audit-logs`           | `audit:read` (admin) | Filters: `action`, `user_id`, `entity_type`, `entity_id`, `from`, `to` |
| GET    | `/auth/callback`            | public (email links) | Exchanges the emailed `code`, redirects to a same-site `next`          |
| GET    | `/api/indicators`           | `indicators:read`    | Search, filter, sort, paginate; see below                              |
| POST   | `/api/indicators`           | `indicators:write`   | Creates a local indicator; `409` names a duplicate                     |
| GET    | `/api/indicators/:id`       | `indicators:read`    | With tags, linked entities and relationships                           |
| PATCH  | `/api/indicators/:id`       | `indicators:write`   | Fields and tags; type and value are fixed                              |
| DELETE | `/api/indicators/:id`       | `indicators:delete`  | Admins                                                                 |
| GET    | `/api/search`               | signed in            | Global search across readable record types                             |
| any    | `/api/<unknown>`            | -                    | `404` in the envelope (`src/app/api/[...path]`)                        |

Auth behavior worth knowing:

- **No account enumeration.** Wrong password and unknown email give the same `401`; sign-up answers `201`
  for new and existing emails alike and never signs the caller in (they sign in next); forgot-password
  always answers `200`.
- **New accounts are `viewer`.** The role is set by a database trigger and never read from the request;
  bodies are strict, so an extra `role_name` field is a `422`. Promotion is an admin action (Phase 7) or SQL.
- **Disabled accounts** (`profiles.is_active = false`) get `403 ACCOUNT_DISABLED` on every guarded call, even
  with a live session, and cannot sign in.
- **CSRF.** Unsafe methods reject a browser `Origin` that differs from the request host; bodies must be JSON;
  the auth cookies are `SameSite=Lax`.

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
- `DELETE /api/indicators/:id` needs `indicators:delete` (admins). Tags, links and relationships go with it.
- `GET /api/indicators/:id` returns the record with `tags`, `threat_actors`, `campaigns`, `malware`,
  `relationships` (each with `direction` and the other indicator) and `created_by_name`. A malformed or
  unknown id is `404`.

Create, update and delete are audited (`indicator.created`, `indicator.updated`, `indicator.deleted`) with the
type and value in `metadata`.

`GET /api/search?q=<2-200 characters>&limit=<1-10>` (any signed-in user) searches every record type the
caller may read and returns `{ query, groups: [{ kind, label, total, hits: [{ id, title, subtitle, href,
origin }] }] }`. Only indicators are searchable so far; new record types register in
`src/lib/search/service.ts` once their pages exist.

## Adding an endpoint

1. Create `src/app/api/<name>/route.ts` and export handlers built with `publicRoute(...)` or
   `protectedRoute({ permissions: [...] }, ...)` from `src/lib/api/handler.ts`. They handle the same-origin
   check, session + permission guard (denials are audited as `authz.denied`), `no-store`, and error mapping.
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

`npm run api:smoke` (app running, local Supabase up) runs about 105 end-to-end checks: sessions, RBAC per role,
audit entries, sign-up, disabled accounts, the full password-recovery email flow through Mailpit, and the
indicator API (search, filters, sorting, paging, every write rule, audit, global search). It works
through nginx too: `SMOKE_BASE_URL=http://localhost:8080 npm run api:smoke`.

## Supabase Auth settings a hosted project must match

Configured for the local stack in `supabase/config.toml`; set the same in the Supabase dashboard (Phase 9
documents deployment): password policy (minimum length 10, lower + upper + digits), redirect URLs that allow
`<app url>/**`, email confirmation on, and the sign-up toggle off if the deployment is invite-only.
