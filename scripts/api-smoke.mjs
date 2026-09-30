// End-to-end smoke test of the auth + RBAC + audit + indicators + intelligence + vulnerabilities API
// against a RUNNING app and the local
// Supabase stack (npm run db:start, then npm run dev or npm start). Local only: it signs in with the
// demo users, creates a throwaway user through the public signup endpoint, reads the recovery email
// from Mailpit, and deletes that user again with the service-role key from .env.local.
//
//   npm run api:smoke                        # against http://localhost:3000
//   SMOKE_BASE_URL=http://localhost:8080 npm run api:smoke   # through nginx
//
// Supabase limits sign-ins/sign-ups to 30 per 5 minutes per IP, so avoid back-to-back runs.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const BASE = process.env.SMOKE_BASE_URL ?? "http://localhost:3000";
const MAILPIT = process.env.MAILPIT_URL ?? "http://127.0.0.1:54324";
const DEMO_PASSWORD = "ArcRadar-Demo-1!";

function loadEnv() {
  const env = {};
  for (const line of readFileSync(new URL("../.env.local", import.meta.url), "utf8").split(
    /\r?\n/,
  )) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
  }
  return env;
}
const env = loadEnv();
const SUPABASE_URL = env.NEXT_PUBLIC_SUPABASE_URL;
const SERVICE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;

class Jar {
  cookies = new Map();
  ingest(response) {
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split(";");
      const index = pair.indexOf("=");
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      const maxAge = attributes.map((a) => /^\s*max-age=(-?\d+)/i.exec(a)?.[1]).find(Boolean);
      if (value === "" || (maxAge !== undefined && Number(maxAge) <= 0)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

async function call(jar, method, path, { body, headers = {}, redirect = "manual" } = {}) {
  const init = {
    method,
    redirect,
    headers: { ...headers },
    signal: AbortSignal.timeout(20_000),
  };
  if (jar?.cookies.size) init.headers.cookie = jar.header();
  if (body !== undefined) {
    init.headers["content-type"] ??= "application/json";
    init.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const response = await fetch(path.startsWith("http") ? path : `${BASE}${path}`, init);
  jar?.ingest(response);
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: response.status, json, text, headers: response.headers };
}

let failures = 0;
let passes = 0;
function check(name, condition, detail) {
  if (condition) {
    passes += 1;
    console.log(`  ok    ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${name}${detail === undefined ? "" : `  -> ${JSON.stringify(detail)}`}`);
  }
}
const section = (title) => console.log(`\n${title}`);
const code = (r) => r.json?.error?.code;

async function loginAs(email, password = DEMO_PASSWORD) {
  const jar = new Jar();
  const response = await call(jar, "POST", "/api/auth/login", { body: { email, password } });
  return { jar, response };
}

async function adminRest(method, path, body) {
  const response = await fetch(`${SUPABASE_URL}${path}`, {
    method,
    headers: {
      apikey: SERVICE_KEY,
      authorization: `Bearer ${SERVICE_KEY}`,
      "content-type": "application/json",
      prefer: "return=minimal",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  return { status: response.status, text: await response.text() };
}

async function latestMailTo(address, notBeforeIds = new Set()) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const list = await (await fetch(`${MAILPIT}/api/v1/messages`)).json();
    const message = list.messages?.find(
      (m) => !notBeforeIds.has(m.ID) && m.To?.some((t) => t.Address === address),
    );
    if (message) return (await fetch(`${MAILPIT}/api/v1/message/${message.ID}`)).json();
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return null;
}

async function main() {
  console.log(`ArcRadar API smoke test against ${BASE}`);

  section("Basics");
  const health = await call(null, "GET", "/api/health");
  check(
    "GET /api/health is 200 with Supabase ok",
    health.status === 200 && health.json?.data?.supabase === "ok",
    health.json,
  );
  const missing = await call(null, "GET", "/api/does-not-exist");
  check(
    "unknown API path answers the JSON envelope (404)",
    missing.status === 404 && code(missing) === "NOT_FOUND",
    missing.text.slice(0, 120),
  );
  const anonMe = await call(null, "GET", "/api/auth/me");
  check(
    "GET /api/auth/me without a session is 401",
    anonMe.status === 401 && code(anonMe) === "UNAUTHENTICATED",
    anonMe.json,
  );
  check(
    "API responses are no-store and carry a request id",
    anonMe.headers.get("cache-control") === "no-store" && !!anonMe.headers.get("x-request-id"),
  );
  const anonAudit = await call(null, "GET", "/api/audit-logs");
  check("GET /api/audit-logs without a session is 401", anonAudit.status === 401, anonAudit.status);

  section("Login validation and failures");
  const badBody = await call(null, "POST", "/api/auth/login", { body: { email: "nope" } });
  check(
    "malformed login body is 422",
    badBody.status === 422 && code(badBody) === "VALIDATION_ERROR",
    badBody.json,
  );
  const wrongType = await call(null, "POST", "/api/auth/login", {
    body: "a=b",
    headers: { "content-type": "text/plain" },
  });
  check("non-JSON content type is 415", wrongType.status === 415, wrongType.status);
  const cross = await call(null, "POST", "/api/auth/login", {
    body: { email: "admin@arcradar.test", password: DEMO_PASSWORD },
    headers: { origin: "https://evil.example" },
  });
  check("cross-origin login POST is 403", cross.status === 403, cross.json);
  const wrongPassword = await loginAs("admin@arcradar.test", "Wrong-Password-1");
  const unknownEmail = await loginAs("nobody-smoke@arcradar.test", "Wrong-Password-1");
  check(
    "wrong password is 401 INVALID_CREDENTIALS",
    wrongPassword.response.status === 401 && code(wrongPassword.response) === "INVALID_CREDENTIALS",
    wrongPassword.response.json,
  );
  check(
    "unknown email gives the identical response (no enumeration)",
    unknownEmail.response.status === 401 &&
      unknownEmail.response.text === wrongPassword.response.text,
  );
  check("failed login sets no session cookie", wrongPassword.jar.cookies.size === 0);

  section("Sessions and RBAC");
  const viewer = await loginAs("viewer@arcradar.test");
  check(
    "viewer login is 200 and sets cookies",
    viewer.response.status === 200 && viewer.jar.cookies.size > 0,
    viewer.response.json,
  );
  check(
    "login response contains no tokens",
    !/access_token|refresh_token/.test(viewer.response.text),
  );
  const viewerMe = await call(viewer.jar, "GET", "/api/auth/me");
  check(
    "viewer /me shows role viewer, read-only permissions",
    viewerMe.json?.data?.profile?.role === "viewer" &&
      viewerMe.json.data.permissions.includes("indicators:read") &&
      !viewerMe.json.data.permissions.includes("indicators:write"),
    viewerMe.json,
  );
  const viewerAudit = await call(viewer.jar, "GET", "/api/audit-logs");
  check(
    "viewer cannot read the audit log (403)",
    viewerAudit.status === 403 && code(viewerAudit) === "FORBIDDEN",
    viewerAudit.json,
  );

  const analyst = await loginAs("analyst@arcradar.test");
  const analystMe = await call(analyst.jar, "GET", "/api/auth/me");
  check(
    "analyst /me shows role analyst with write permission",
    analystMe.json?.data?.profile?.role === "analyst" &&
      analystMe.json.data.permissions.includes("indicators:write") &&
      !analystMe.json.data.permissions.includes("audit:read"),
    analystMe.json,
  );
  const analystAudit = await call(analyst.jar, "GET", "/api/audit-logs");
  check(
    "analyst cannot read the audit log (403)",
    analystAudit.status === 403,
    analystAudit.status,
  );

  const admin = await loginAs("admin@arcradar.test");
  const adminMe = await call(admin.jar, "GET", "/api/auth/me");
  check(
    "admin /me shows role admin with audit:read",
    adminMe.json?.data?.profile?.role === "admin" &&
      adminMe.json.data.permissions.includes("audit:read"),
    adminMe.json,
  );

  section("Audit trail (read as admin)");
  const logs = await call(admin.jar, "GET", "/api/audit-logs?page_size=100");
  const items = logs.json?.data?.items ?? [];
  check(
    "admin can read the audit log with pagination metadata",
    logs.status === 200 && logs.json.data.pagination.page === 1,
    logs.json?.error,
  );
  const viewerId = viewerMe.json?.data?.user?.id;
  check(
    "successful logins are audited with ip/user agent",
    items.some((e) => e.action === "auth.login" && e.user_id === viewerId && e.user_agent),
    items.slice(0, 2),
  );
  check(
    "failed login is audited without the password",
    items.some(
      (e) => e.action === "auth.login_failed" && e.metadata?.reason === "invalid_credentials",
    ) && !JSON.stringify(items).includes("Wrong-Password-1"),
  );
  check(
    "denied access is audited as authz.denied",
    items.some(
      (e) =>
        e.action === "authz.denied" && e.user_id === viewerId && e.entity_id === "/api/audit-logs",
    ),
  );
  const filtered = await call(admin.jar, "GET", "/api/audit-logs?action=authz.denied&page_size=5");
  check(
    "filtering by action works",
    filtered.status === 200 &&
      filtered.json.data.items.length > 0 &&
      filtered.json.data.items.every((e) => e.action === "authz.denied"),
    filtered.json?.error,
  );
  const tooBig = await call(admin.jar, "GET", "/api/audit-logs?page_size=1000");
  check("page_size above the maximum is 422", tooBig.status === 422, tooBig.status);
  const badFilter = await call(admin.jar, "GET", "/api/audit-logs?user_id=not-a-uuid");
  check("invalid filter value is 422", badFilter.status === 422, badFilter.status);

  section("Indicators: read, search, filter, sort, paginate");
  const list = await call(viewer.jar, "GET", "/api/indicators?page_size=5");
  check(
    "viewer can list indicators with tags and pagination",
    list.status === 200 &&
      list.json.data.items.length === 5 &&
      list.json.data.pagination.total >= 41 &&
      Array.isArray(list.json.data.items[0].tags),
    list.json?.error,
  );
  check(
    "every listed record carries its provenance",
    list.json.data.items.every((i) => ["demo", "local", "external"].includes(i.origin)),
  );
  const page2 = await call(viewer.jar, "GET", "/api/indicators?page_size=5&page=2");
  const ids1 = new Set(list.json.data.items.map((i) => i.id));
  check(
    "page 2 does not repeat page 1",
    page2.status === 200 &&
      page2.json.data.items.every((i) => !ids1.has(i.id)) &&
      page2.json.data.pagination.page === 2,
  );
  const beyond = await call(viewer.jar, "GET", "/api/indicators?page=99");
  check(
    "a page past the end is an empty page with the real total, not an error",
    beyond.status === 200 &&
      beyond.json.data.items.length === 0 &&
      beyond.json.data.pagination.total >= 41 &&
      beyond.json.data.pagination.page === 99,
    beyond.json,
  );
  const byTag = await call(viewer.jar, "GET", "/api/indicators?tag=C2&page_size=100");
  check(
    "tag filter is case-insensitive and exact",
    byTag.status === 200 &&
      byTag.json.data.items.length > 0 &&
      byTag.json.data.items.every((i) => i.tags.some((t) => t.name === "c2")),
    byTag.json?.error,
  );
  const text = await call(
    viewer.jar,
    "GET",
    `/api/indicators?q=${encodeURIComponent("harbor lights")}&page_size=100`,
  );
  check(
    "text search ANDs its terms across value, description and tags",
    text.status === 200 &&
      text.json.data.items.length > 0 &&
      text.json.data.items.every(
        (i) => /harbor/i.test(JSON.stringify(i)) && /lights/i.test(JSON.stringify(i)),
      ),
    text.json?.error,
  );
  const tagText = await call(viewer.jar, "GET", "/api/indicators?q=phishing&page_size=100");
  check(
    "text search also matches tag names",
    tagText.status === 200 &&
      tagText.json.data.items.some(
        (i) =>
          i.tags.some((t) => t.name === "phishing") &&
          !/phishing/i.test(`${i.value} ${i.description} ${i.source}`),
      ),
    tagText.json?.data?.pagination,
  );
  const percent = await call(viewer.jar, "GET", "/api/indicators?q=%25");
  check(
    "a percent sign is a literal, not a wildcard",
    percent.status === 200 && percent.json.data.pagination.total === 0,
    percent.json?.data?.pagination,
  );
  const combined = await call(
    viewer.jar,
    "GET",
    "/api/indicators?type=domain&verdict=malicious&sort=confidence&order=desc&page_size=100",
  );
  const conf = combined.json?.data?.items.map((i) => i.confidence) ?? [];
  check(
    "filters combine and sorting works (domain + malicious, confidence desc)",
    combined.status === 200 &&
      conf.length > 0 &&
      combined.json.data.items.every((i) => i.type === "domain" && i.verdict === "malicious") &&
      conf.every((c, i) => i === 0 || conf[i - 1] >= c),
    conf,
  );
  const bySeverity = await call(
    viewer.jar,
    "GET",
    "/api/indicators?sort=severity&order=desc&page_size=3",
  );
  check(
    "severity sorts by rank, not alphabet (critical first)",
    bySeverity.status === 200 && bySeverity.json.data.items[0].severity === "critical",
    bySeverity.json?.data?.items?.map((i) => i.severity),
  );
  const blank = await call(viewer.jar, "GET", "/api/indicators?type=&status=&q=&page_size=2");
  check(
    "blank filter values from a form mean no filter",
    blank.status === 200 && blank.json.data.pagination.total >= 41,
  );
  for (const bad of ["page_size=1000", "sort=password", "type=nope", "order=sideways", "page=0"]) {
    const response = await call(viewer.jar, "GET", `/api/indicators?${bad}`);
    check(
      `invalid query "${bad}" is 422`,
      response.status === 422 && code(response) === "VALIDATION_ERROR",
      response.status,
    );
  }

  section("Indicators: write permissions");
  const newValue = `Smoke-${Date.now()}.EXAMPLE`;
  const asViewer = await call(viewer.jar, "POST", "/api/indicators", {
    body: { type: "domain", value: newValue },
  });
  check("viewer cannot create (403)", asViewer.status === 403, asViewer.json);
  const viewerPatch = await call(
    viewer.jar,
    "PATCH",
    `/api/indicators/${list.json.data.items[0].id}`,
    { body: { severity: "low" } },
  );
  check("viewer cannot edit (403)", viewerPatch.status === 403, viewerPatch.status);
  const viewerDelete = await call(
    viewer.jar,
    "DELETE",
    `/api/indicators/${list.json.data.items[0].id}`,
  );
  check("viewer cannot delete (403)", viewerDelete.status === 403, viewerDelete.status);

  section("Indicators: create, edit, delete");
  const analystMeId = analystMe.json?.data?.user?.id;
  const created = await call(analyst.jar, "POST", "/api/indicators", {
    body: {
      type: "domain",
      value: newValue,
      severity: "high",
      verdict: "suspicious",
      confidence: 70,
      description: "  Created by the smoke test.  ",
      tags: ["Smoke Test", "smoke test", "smoke-a"],
    },
  });
  const indicator = created.json?.data;
  check(
    "analyst creates an indicator (201)",
    created.status === 201 && indicator?.type === "domain",
    created.json,
  );
  check(
    "the value is stored canonically (lower-case) and trimmed text is kept tidy",
    indicator?.value === newValue.toLowerCase() &&
      indicator?.description === "Created by the smoke test.",
  );
  check(
    "new records are always local and owned by their creator",
    indicator?.origin === "local" && indicator?.created_by === analystMeId,
    [indicator?.origin, indicator?.created_by],
  );
  check(
    "duplicate tags collapse (ignoring case)",
    indicator?.tags
      .map((t) => t.name)
      .sort()
      .join("|") === "Smoke Test|smoke-a",
    indicator?.tags,
  );
  const dupe = await call(analyst.jar, "POST", "/api/indicators", {
    body: { type: "domain", value: newValue.toUpperCase() },
  });
  check(
    "a duplicate (other case) is 409 and names the existing indicator",
    dupe.status === 409 && dupe.json?.error?.details?.existing_id === indicator?.id,
    dupe.json,
  );
  const badIp = await call(analyst.jar, "POST", "/api/indicators", {
    body: { type: "ipv4", value: "999.1.1.1" },
  });
  check(
    "a malformed value is 422 on the value field",
    badIp.status === 422 && badIp.json?.error?.details?.issues?.some((i) => i.path === "value"),
    badIp.json,
  );
  for (const [name, body] of [
    ["origin", { type: "domain", value: "forged.example", origin: "external" }],
    ["created_by", { type: "domain", value: "forged2.example", created_by: analystMeId }],
    ["an unknown type", { type: "nope", value: "x" }],
    [
      "reversed dates",
      {
        type: "domain",
        value: "dates.example",
        first_seen: "2026-02-01T00:00:00Z",
        last_seen: "2026-01-01T00:00:00Z",
      },
    ],
  ]) {
    const response = await call(analyst.jar, "POST", "/api/indicators", { body });
    check(`create rejects ${name} (422)`, response.status === 422, response.json?.error);
  }

  const detail = await call(viewer.jar, "GET", `/api/indicators/${indicator?.id}`);
  check(
    "detail returns the indicator with tags and relationships",
    detail.status === 200 &&
      detail.json.data.id === indicator?.id &&
      Array.isArray(detail.json.data.relationships),
    detail.json?.error,
  );
  const seeded = await call(
    viewer.jar,
    "GET",
    `/api/indicators?q=${encodeURIComponent("198.51.100.23")}`,
  );
  const seededDetail = await call(
    viewer.jar,
    "GET",
    `/api/indicators/${seeded.json?.data?.items?.find((i) => i.value === "198.51.100.23")?.id}`,
  );
  check(
    "a seeded indicator shows its relationships and is labelled demo",
    seededDetail.status === 200 &&
      seededDetail.json.data.relationships.length > 0 &&
      seededDetail.json.data.origin === "demo",
    seededDetail.json?.data && { rel: seededDetail.json.data.relationships },
  );

  const patched = await call(analyst.jar, "PATCH", `/api/indicators/${indicator?.id}`, {
    body: { severity: "critical", description: "", tags: ["smoke-b"] },
  });
  check(
    "analyst edits fields and replaces tags",
    patched.status === 200 &&
      patched.json.data.severity === "critical" &&
      patched.json.data.description === null &&
      patched.json.data.tags.map((t) => t.name).join() === "smoke-b",
    patched.json,
  );
  check(
    "editing does not change provenance or ownership",
    patched.json?.data?.origin === "local" && patched.json?.data?.created_by === analystMeId,
  );
  for (const [name, body] of [
    ["value", { value: "other.example" }],
    ["type", { type: "url" }],
    ["origin", { origin: "demo" }],
    ["an empty patch", {}],
    ["reversed dates", { first_seen: "2026-02-01T00:00:00Z", last_seen: "2026-01-01T00:00:00Z" }],
  ]) {
    const response = await call(analyst.jar, "PATCH", `/api/indicators/${indicator?.id}`, { body });
    check(`edit rejects ${name} (422)`, response.status === 422, response.json?.error);
  }
  const lastSeenOnly = await call(analyst.jar, "PATCH", `/api/indicators/${indicator?.id}`, {
    body: { last_seen: "2000-01-01T00:00:00Z" },
  });
  check(
    "a last-seen before the stored first-seen is a 422 naming the field",
    lastSeenOnly.status === 422 &&
      lastSeenOnly.json?.error?.details?.issues?.some((i) => i.path === "last_seen"),
    lastSeenOnly.json,
  );
  const patchMissing = await call(
    analyst.jar,
    "PATCH",
    "/api/indicators/00000000-0000-4000-8000-000000000000",
    { body: { severity: "low" } },
  );
  check(
    "editing an unknown indicator is 404",
    patchMissing.status === 404,
    patchMissing.json?.error,
  );
  const analystDelete = await call(analyst.jar, "DELETE", `/api/indicators/${indicator?.id}`);
  check("analyst cannot delete (403)", analystDelete.status === 403, analystDelete.status);
  const adminDelete = await call(admin.jar, "DELETE", `/api/indicators/${indicator?.id}`);
  check(
    "admin deletes the indicator",
    adminDelete.status === 200 && adminDelete.json?.data?.deleted === true,
    adminDelete.json,
  );
  check(
    "the deleted indicator is gone (404), also for a repeat delete",
    (await call(viewer.jar, "GET", `/api/indicators/${indicator?.id}`)).status === 404 &&
      (await call(admin.jar, "DELETE", `/api/indicators/${indicator?.id}`)).status === 404,
  );
  check(
    "a malformed id is 404, not an error",
    (await call(viewer.jar, "GET", "/api/indicators/not-a-uuid")).status === 404,
  );
  await adminRest("DELETE", "/rest/v1/tags?name=ilike.smoke*");

  section("Indicators: audit trail and global search");
  const indicatorTrail = await call(
    admin.jar,
    "GET",
    "/api/audit-logs?entity_type=indicator&page_size=50",
  );
  const indicatorActions = indicatorTrail.json?.data?.items
    ?.filter((e) => e.entity_id === indicator?.id)
    .map((e) => e.action)
    .sort();
  check(
    "create, update and delete are audited against the indicator",
    indicatorActions?.join() === "indicator.created,indicator.deleted,indicator.updated",
    indicatorActions,
  );
  const deletedEntry = indicatorTrail.json?.data?.items?.find(
    (e) => e.entity_id === indicator?.id && e.action === "indicator.deleted",
  );
  check(
    "the delete entry keeps what was deleted",
    deletedEntry?.metadata?.value === newValue.toLowerCase() &&
      deletedEntry?.user_id === adminMe.json?.data?.user?.id,
    deletedEntry?.metadata,
  );
  const search = await call(viewer.jar, "GET", "/api/search?q=harbor");
  const hit = search.json?.data?.groups?.[0]?.hits?.[0];
  check(
    "global search returns grouped hits with links and provenance",
    search.status === 200 &&
      search.json.data.groups[0].kind === "indicator" &&
      hit?.href?.startsWith("/indicators/") &&
      hit?.origin === "demo" &&
      typeof hit?.subtitle === "string",
    search.json?.data,
  );
  check(
    "global search rejects a one-character query (422)",
    (await call(viewer.jar, "GET", "/api/search?q=a")).status === 422,
  );
  check(
    "global search needs a session (401)",
    (await call(null, "GET", "/api/search?q=harbor")).status === 401,
  );
  check(
    "indicator endpoints need a session (401)",
    (await call(null, "GET", "/api/indicators")).status === 401,
  );

  section("Intelligence lookups (demo provider, no live keys)");
  const lookup = (jar, kind, value) =>
    call(jar, "GET", `/api/intel/${kind}?value=${encodeURIComponent(value)}`);
  const ipLookup = await lookup(viewer.jar, "ip", "198.51.100.23");
  const ipData = ipLookup.json?.data;
  check(
    "an IP lookup answers from the demo provider, labelled demo, with the network details",
    ipLookup.status === 200 &&
      ipData?.results?.length === 1 &&
      ipData.results[0].provider.id === "demo" &&
      ipData.results[0].provider.origin === "demo" &&
      ipData.results[0].profile.kind === "ip" &&
      ipData.results[0].profile.asn === 64501 &&
      ipData.results[0].profile.reputation.verdict === "malicious",
    ipLookup.json?.error ?? ipData?.results,
  );
  check(
    "the answer says what happened with each provider and that nothing live is connected",
    ipData?.attempts?.length === 1 &&
      ipData.attempts[0].status === "ok" &&
      ipData.live_providers.length === 0 &&
      ipData.fallback === false &&
      ipData.value === "198.51.100.23" &&
      ipData.indicator_type === "ipv4",
    ipData?.attempts,
  );
  check(
    "it comes with what the workspace knows: the tracked indicator, relationships and a timeline",
    ipData?.local?.indicator?.value === "198.51.100.23" &&
      ipData.local.indicator.relationships.length >= 2 &&
      ipData.local.timeline.length >= 2 &&
      ipData.local.timeline.every((entry) => entry.at && entry.kind && entry.title),
    ipData?.local?.timeline,
  );
  check(
    "viewers may not ask live providers, analysts may (no key is configured, so nothing is asked)",
    ipData?.live_allowed === false &&
      (await lookup(analyst.jar, "ip", "198.51.100.23")).json?.data?.live_allowed === true,
  );

  const domainLookup = await lookup(viewer.jar, "domain", "Harbor-Lights-C2.EXAMPLE");
  const domainProfile = domainLookup.json?.data?.results?.[0]?.profile;
  check(
    "a domain lookup canonicalizes the value and returns registration, DNS and related IPs",
    domainLookup.status === 200 &&
      domainLookup.json.data.value === "harbor-lights-c2.example" &&
      domainProfile?.kind === "domain" &&
      domainProfile.related_ips.includes("198.51.100.23") &&
      domainProfile.dns_records.length >= 1 &&
      domainProfile.nameservers.length >= 1 &&
      domainProfile.registrar,
    domainLookup.json?.error ?? domainProfile,
  );
  const urlLookup = await lookup(
    viewer.jar,
    "url",
    "http://invoice-download.example/files/invoice_2026.zip",
  );
  check(
    "a URL lookup returns reputation, detections and the redirect chain, never fetching the URL",
    urlLookup.status === 200 &&
      urlLookup.json.data.results[0].profile.kind === "url" &&
      urlLookup.json.data.results[0].profile.host === "invoice-download.example" &&
      urlLookup.json.data.results[0].profile.redirect_chain.length === 2 &&
      urlLookup.json.data.results[0].profile.detections.malicious > 0,
    urlLookup.json?.error,
  );
  const sample = (algorithm) =>
    createHash(algorithm).update("arcradar-demo-sample-1", "utf8").digest("hex");
  const hashLookups = await Promise.all(
    [sample("md5"), sample("sha1"), sample("sha256").toUpperCase()].map((hash) =>
      lookup(viewer.jar, "hash", hash),
    ),
  );
  check(
    "MD5, SHA-1 and SHA-256 (any case) of one sample all find the same file",
    hashLookups.every(
      (r) =>
        r.status === 200 &&
        r.json.data.results[0]?.profile.file_name === "invoice_viewer.exe" &&
        r.json.data.results[0].profile.malware_families[0] === "NightLoader",
    ) &&
      hashLookups.map((r) => r.json.data.results[0].profile.hash_type).join() === "md5,sha1,sha256",
    hashLookups.map((r) => r.json?.error),
  );
  const noRecord = await lookup(viewer.jar, "ip", "203.0.113.190");
  check(
    "a value the demo dataset does not know answers 200 with no results and 'not_found'",
    noRecord.status === 200 &&
      noRecord.json.data.results.length === 0 &&
      noRecord.json.data.attempts[0].status === "not_found" &&
      noRecord.json.data.local.indicator?.value === "203.0.113.190",
    noRecord.json?.data?.attempts,
  );
  const privateIp = await lookup(viewer.jar, "ip", "10.0.0.1");
  check(
    "a private address is accepted and answered locally (it would never be sent out)",
    privateIp.status === 200 && privateIp.json.data.results.length === 0,
    privateIp.json?.error,
  );

  check(
    "a malformed value is a 422 that names the field",
    (await lookup(viewer.jar, "ip", "not-an-ip")).status === 422 &&
      (await lookup(viewer.jar, "ip", "not-an-ip")).json.error.details.issues[0].path === "value" &&
      (await lookup(viewer.jar, "domain", "http://x.example/a")).status === 422 &&
      (await lookup(viewer.jar, "hash", "abc123")).status === 422 &&
      (await lookup(viewer.jar, "url", "javascript:alert(1)")).status === 422,
  );
  check(
    "a missing value is a 422 and an unknown kind is a 404",
    (await call(viewer.jar, "GET", "/api/intel/ip")).status === 422 &&
      (await call(viewer.jar, "GET", "/api/intel/mac?value=x")).status === 404,
  );
  check(
    "lookups need a session (401)",
    (await call(null, "GET", "/api/intel/ip?value=8.8.8.8")).status === 401,
  );
  const intelAudit = await call(admin.jar, "GET", "/api/audit-logs?entity_type=intel");
  check(
    "demo lookups leave no audit entry (nothing left the workspace)",
    intelAudit.status === 200 && intelAudit.json.data.pagination.total === 0,
    intelAudit.json?.data?.pagination,
  );

  section("Vulnerabilities: list, search, filter, sort, paginate, detail, statistics");
  const vulns = await call(viewer.jar, "GET", "/api/vulnerabilities?page_size=100");
  check(
    "viewer can list vulnerabilities, each with its provenance",
    vulns.status === 200 &&
      vulns.json.data.pagination.total >= 12 &&
      vulns.json.data.items.every((v) => ["demo", "local", "external"].includes(v.origin)),
    vulns.json?.error,
  );
  const published = vulns.json.data.items.map((v) => Date.parse(v.published_at));
  check(
    "newest published comes first by default",
    published.every((time, index) => index === 0 || time <= published[index - 1]),
  );
  const log4j = await call(viewer.jar, "GET", "/api/vulnerabilities?q=log4j");
  check(
    "text search finds a CVE by its title words",
    log4j.status === 200 && log4j.json.data.items.some((v) => v.cve_id === "CVE-2021-44228"),
    log4j.json?.error,
  );
  const byId = await call(viewer.jar, "GET", "/api/vulnerabilities?q=cve-2021-44228");
  check(
    "text search finds a CVE by its id, whatever the case",
    byId.json?.data?.items?.length === 1 && byId.json.data.items[0].cve_id === "CVE-2021-44228",
  );
  const byVendor = await call(viewer.jar, "GET", "/api/vulnerabilities?q=microsoft&page_size=100");
  check(
    "text search also matches affected vendors and products",
    byVendor.json?.data?.items?.some((v) => v.cve_id === "CVE-2017-0144") &&
      byVendor.json.data.items.some((v) => v.cve_id === "CVE-2021-26855"),
    byVendor.json?.error,
  );
  check(
    "a term that matches nothing gives an empty list, not an error",
    (await call(viewer.jar, "GET", "/api/vulnerabilities?q=zzz-nothing")).json?.data?.pagination
      ?.total === 0,
  );
  const critical = await call(
    viewer.jar,
    "GET",
    "/api/vulnerabilities?severity=critical&page_size=100",
  );
  check(
    "severity filter is exact",
    critical.status === 200 &&
      critical.json.data.items.length > 0 &&
      critical.json.data.items.every((v) => v.severity === "critical"),
  );
  const poc = await call(viewer.jar, "GET", "/api/vulnerabilities?exploit_status=poc_available");
  check(
    "exploit status filter is exact",
    poc.json?.data?.items?.length > 0 &&
      poc.json.data.items.every((v) => v.exploit_status === "poc_available"),
  );
  const highScore = await call(
    viewer.jar,
    "GET",
    "/api/vulnerabilities?min_cvss=9.8&page_size=100",
  );
  check(
    "minimum CVSS filter keeps only records at or above the score",
    highScore.json?.data?.items?.length > 0 &&
      highScore.json.data.items.every((v) => v.cvss_score >= 9.8),
  );
  check(
    "origin filter separates demo from external data",
    (await call(viewer.jar, "GET", "/api/vulnerabilities?origin=demo")).json?.data?.pagination
      ?.total >= 12 &&
      (await call(viewer.jar, "GET", "/api/vulnerabilities?origin=external")).json?.data?.pagination
        ?.total === 0,
  );
  const byScoreDesc = await call(
    viewer.jar,
    "GET",
    "/api/vulnerabilities?sort=cvss_score&order=desc&page_size=100",
  );
  const scores = byScoreDesc.json?.data?.items?.map((v) => v.cvss_score) ?? [];
  check(
    "sorting by CVSS score descending is ordered",
    scores.length >= 12 &&
      scores.every((score, index) => index === 0 || score <= scores[index - 1]),
    scores,
  );
  const byScoreAsc = await call(
    viewer.jar,
    "GET",
    "/api/vulnerabilities?sort=cvss_score&order=asc&page_size=100",
  );
  const ascending = byScoreAsc.json?.data?.items?.map((v) => v.cvss_score) ?? [];
  check(
    "sorting by CVSS score ascending is ordered",
    ascending.every((score, index) => index === 0 || score >= ascending[index - 1]),
  );
  const vulnBySeverity = await call(
    viewer.jar,
    "GET",
    "/api/vulnerabilities?sort=severity&order=desc&page_size=100",
  );
  check(
    "sorting by severity puts the most severe first, not alphabetical order",
    vulnBySeverity.json?.data?.items?.[0]?.severity === "critical",
  );
  const vulnPage3 = await call(viewer.jar, "GET", "/api/vulnerabilities?page_size=5&page=3");
  const vulnBeyond = await call(viewer.jar, "GET", "/api/vulnerabilities?page=99");
  check(
    "paging works, and a page past the end is an empty page with the real total",
    vulnPage3.json?.data?.items?.length === 2 &&
      vulnPage3.json.data.pagination.total_pages === 3 &&
      vulnBeyond.status === 200 &&
      vulnBeyond.json.data.items.length === 0 &&
      vulnBeyond.json.data.pagination.total >= 12,
    vulnBeyond.json,
  );
  check(
    "invalid query values are 422",
    (await call(viewer.jar, "GET", "/api/vulnerabilities?severity=nope")).status === 422 &&
      (await call(viewer.jar, "GET", "/api/vulnerabilities?min_cvss=11")).status === 422 &&
      (await call(viewer.jar, "GET", "/api/vulnerabilities?sort=description")).status === 422 &&
      (await call(viewer.jar, "GET", "/api/vulnerabilities?page_size=101")).status === 422,
  );

  const vulnDetail = await call(viewer.jar, "GET", "/api/vulnerabilities/cve-2021-44228");
  check(
    "a CVE has its score, affected products, references and the indicator that tracks it",
    vulnDetail.status === 200 &&
      vulnDetail.json.data.cve_id === "CVE-2021-44228" &&
      vulnDetail.json.data.cvss_score === 10 &&
      vulnDetail.json.data.affected_products.length >= 1 &&
      vulnDetail.json.data.affected_products[0].vendor === "Apache" &&
      vulnDetail.json.data.reference_urls.length >= 1 &&
      vulnDetail.json.data.indicator?.id &&
      vulnDetail.json.data.origin === "demo",
    vulnDetail.json?.error ?? vulnDetail.json?.data,
  );
  check(
    "an unknown or malformed CVE id is 404",
    (await call(viewer.jar, "GET", "/api/vulnerabilities/CVE-2099-0001")).status === 404 &&
      (await call(viewer.jar, "GET", "/api/vulnerabilities/not-a-cve")).status === 404,
  );
  const stats = await call(viewer.jar, "GET", "/api/vulnerabilities/stats");
  const rows = stats.json?.data?.by_severity ?? [];
  check(
    "statistics list every severity, most severe first, and add up",
    stats.status === 200 &&
      rows.map((row) => row.severity).join() === "critical,high,medium,low,info" &&
      rows.reduce((sum, row) => sum + row.total, 0) === stats.json.data.total &&
      stats.json.data.total === vulns.json.data.pagination.total &&
      stats.json.data.exploited > 0 &&
      rows.every((row) => row.exploited <= row.total),
    stats.json?.data,
  );
  check(
    "vulnerability endpoints need a session (401)",
    (await call(null, "GET", "/api/vulnerabilities")).status === 401 &&
      (await call(null, "GET", "/api/vulnerabilities/stats")).status === 401 &&
      (await call(null, "GET", "/api/vulnerabilities/CVE-2021-44228")).status === 401,
  );

  const importBody = { cve_id: "CVE-2099-0001" };
  check(
    "importing from a provider needs vulnerabilities:write: viewers and analysts get 403",
    (await call(viewer.jar, "POST", "/api/vulnerabilities/import", { body: importBody })).status ===
      403 &&
      (await call(analyst.jar, "POST", "/api/vulnerabilities/import", { body: importBody }))
        .status === 403 &&
      (await call(null, "POST", "/api/vulnerabilities/import", { body: importBody })).status ===
        401,
  );
  const badImport = await call(admin.jar, "POST", "/api/vulnerabilities/import", {
    body: { cve_id: "not-a-cve", origin: "external" },
  });
  check(
    "an import body is strict: bad id and extra fields are 422",
    badImport.status === 422,
    badImport.json,
  );
  if (env.NVD_API_KEY) {
    console.log("  skip  no-provider import check (NVD_API_KEY is set: the import would call NVD)");
  } else {
    const noProvider = await call(admin.jar, "POST", "/api/vulnerabilities/import", {
      body: importBody,
    });
    check(
      "an administrator gets 503 when no vulnerability provider is connected, and nothing is stored",
      noProvider.status === 503 &&
        code(noProvider) === "DEPENDENCY_UNAVAILABLE" &&
        (await call(viewer.jar, "GET", "/api/vulnerabilities?origin=external")).json.data.pagination
          .total === 0,
      noProvider.json,
    );
  }

  section("Global search: vulnerabilities and lookup suggestions");
  const logSearch = await call(viewer.jar, "GET", "/api/search?q=log4j");
  const vulnGroup = logSearch.json?.data?.groups?.find((g) => g.kind === "vulnerability");
  check(
    "global search finds CVEs, with a link, severity, score and provenance",
    vulnGroup?.hits?.[0]?.href === "/vulnerabilities/CVE-2021-44228" &&
      vulnGroup.hits[0].origin === "demo" &&
      /Critical · CVSS 10\.0/.test(vulnGroup.hits[0].subtitle),
    logSearch.json?.data,
  );
  const ipSearch = await call(viewer.jar, "GET", "/api/search?q=198.51.100.23");
  check(
    "an IP address is recognized and a lookup is offered first (structure only, no verdict)",
    ipSearch.json?.data?.groups?.[0]?.kind === "lookup" &&
      ipSearch.json.data.groups[0].hits[0].href === "/intelligence/ip?q=198.51.100.23" &&
      ipSearch.json.data.groups[0].hits[0].origin === null &&
      !/malicious|suspicious|safe/i.test(ipSearch.json.data.groups[0].hits[0].subtitle) &&
      ipSearch.json.data.groups.some((g) => g.kind === "indicator"),
    ipSearch.json?.data?.groups?.map((g) => g.kind),
  );

  // ---------------------------------------------------------------------------------------------
  // Phase 6: alerts, investigations, threat intelligence
  // ---------------------------------------------------------------------------------------------
  const stamp = Date.now();
  const analystId = analystMe.json?.data?.user?.id;
  const NIL_UUID = "00000000-0000-4000-8000-000000000000";
  const problems = (r) => r.json?.error?.details?.issues?.map((i) => i.path) ?? [];

  section("Alerts: read, search, filter, sort, paginate, statistics");
  const anonAlerts = await call(null, "GET", "/api/alerts");
  check("GET /api/alerts without a session is 401", anonAlerts.status === 401, anonAlerts.status);
  const alertList = await call(viewer.jar, "GET", "/api/alerts");
  const alertItems = alertList.json?.data?.items ?? [];
  check(
    "viewer lists alerts, each with its provenance, indicator and assignee",
    alertList.status === 200 &&
      alertItems.length > 0 &&
      alertItems.every((a) => a.origin && "indicator" in a && "assignee" in a),
    alertList.json?.data?.pagination,
  );
  const alertTotal = alertList.json?.data?.pagination?.total ?? 0;
  const criticalAlerts = await call(viewer.jar, "GET", "/api/alerts?severity=critical");
  check(
    "severity filter narrows the list",
    criticalAlerts.json?.data?.items?.every((a) => a.severity === "critical") &&
      criticalAlerts.json.data.pagination.total > 0 &&
      criticalAlerts.json.data.pagination.total < alertTotal,
    criticalAlerts.json?.data?.pagination,
  );
  const beaconAlerts = await call(viewer.jar, "GET", "/api/alerts?q=beacon%20harbor");
  check(
    "all search words must match (title, source or indicator value)",
    beaconAlerts.json?.data?.items?.length > 0 &&
      beaconAlerts.json.data.items.every(
        (a) => /beacon/i.test(a.title) && /harbor/i.test(a.title + (a.indicator?.value ?? "")),
      ),
    beaconAlerts.json?.data?.items?.map((a) => a.title),
  );
  const wildcardAlerts = await call(viewer.jar, "GET", "/api/alerts?q=%25");
  check(
    "a literal % in the search text matches nothing instead of everything",
    wildcardAlerts.status === 200 && wildcardAlerts.json?.data?.pagination?.total === 0,
    wildcardAlerts.json?.data?.pagination,
  );
  const unassigned = await call(viewer.jar, "GET", "/api/alerts?assignee=none");
  check(
    "assignee=none lists only alerts nobody has picked up",
    unassigned.json?.data?.items?.every((a) => a.assigned_to === null),
    unassigned.json?.data?.pagination,
  );
  const alertsBySeverity = await call(
    viewer.jar,
    "GET",
    "/api/alerts?sort=severity&order=desc&page_size=100",
  );
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const ranks = (alertsBySeverity.json?.data?.items ?? []).map((a) => rank[a.severity]);
  check(
    "sorting by severity puts the most severe first",
    ranks.length > 1 && ranks.every((value, index) => index === 0 || ranks[index - 1] >= value),
    ranks,
  );
  for (const [name, path] of [
    ["an unknown status", "/api/alerts?status=bogus"],
    ["an unknown sort", "/api/alerts?sort=title"],
    ["a bad assignee", "/api/alerts?assignee=everyone"],
  ]) {
    const bad = await call(viewer.jar, "GET", path);
    check(`${name} is 422`, bad.status === 422, bad.json);
  }
  const pastEnd = await call(viewer.jar, "GET", "/api/alerts?page=9999");
  check(
    "a page past the last one is an empty page, not an error",
    pastEnd.status === 200 &&
      pastEnd.json?.data?.items?.length === 0 &&
      pastEnd.json.data.pagination.total === alertTotal,
    pastEnd.json?.data?.pagination,
  );
  const alertStats = await call(viewer.jar, "GET", "/api/alerts/stats");
  check(
    "statistics cover every status in lifecycle order and add up to the total",
    alertStats.json?.data?.by_status?.map((s) => s.status).join(",") ===
      "new,acknowledged,investigating,resolved,false_positive" &&
      alertStats.json.data.total === alertTotal &&
      alertStats.json.data.by_status.reduce((sum, s) => sum + s.total, 0) === alertTotal,
    alertStats.json?.data,
  );
  const firstAlert = await call(viewer.jar, "GET", `/api/alerts/${alertItems[0]?.id}`);
  check(
    "an alert opens with its indicator, event and investigations",
    firstAlert.status === 200 &&
      "event" in (firstAlert.json?.data ?? {}) &&
      Array.isArray(firstAlert.json.data.investigations),
    firstAlert.json?.data && Object.keys(firstAlert.json.data),
  );
  const malformedAlert = await call(viewer.jar, "GET", "/api/alerts/not-a-uuid");
  const unknownAlert = await call(viewer.jar, "GET", `/api/alerts/${NIL_UUID}`);
  check(
    "a malformed or unknown alert id is 404",
    malformedAlert.status === 404 && unknownAlert.status === 404,
    [malformedAlert.status, unknownAlert.status],
  );

  section("Alerts: lifecycle, assignment, permissions");
  const viewerCreatesAlert = await call(viewer.jar, "POST", "/api/alerts", {
    body: { title: "Viewer alert" },
  });
  check(
    "a viewer cannot create an alert (403)",
    viewerCreatesAlert.status === 403,
    viewerCreatesAlert.json,
  );
  const alertTitle = `Smoke alert ${stamp}`;
  const madeAlert = await call(analyst.jar, "POST", "/api/alerts", {
    body: { title: `  ${alertTitle}  `, severity: "high", description: "" },
  });
  const smokeAlert = madeAlert.json?.data;
  check(
    "analyst creates an alert (201): new, manual, local, unassigned, title trimmed",
    madeAlert.status === 201 &&
      smokeAlert?.title === alertTitle &&
      smokeAlert.status === "new" &&
      smokeAlert.source === "manual" &&
      smokeAlert.origin === "local" &&
      smokeAlert.assigned_to === null &&
      smokeAlert.description === null,
    madeAlert.json,
  );
  for (const [name, body] of [
    ["origin", { title: "x", origin: "external" }],
    ["source", { title: "x", source: "wazuh" }],
    ["status", { title: "x", status: "resolved" }],
    ["an empty title", { title: "   " }],
  ]) {
    const rejected = await call(analyst.jar, "POST", "/api/alerts", { body });
    check(`an alert body with ${name} is rejected (422)`, rejected.status === 422, rejected.json);
  }
  const base = `/api/alerts/${smokeAlert?.id}`;
  const viewerAlertPatch = await call(viewer.jar, "PATCH", base, {
    body: { status: "acknowledged" },
  });
  check(
    "a viewer cannot change an alert (403)",
    viewerAlertPatch.status === 403,
    viewerAlertPatch.json,
  );
  const emptyPatch = await call(analyst.jar, "PATCH", base, { body: {} });
  const extraPatch = await call(analyst.jar, "PATCH", base, {
    body: { status: "acknowledged", severity: "low" },
  });
  check(
    "an empty or over-wide update is 422",
    emptyPatch.status === 422 && extraPatch.status === 422,
    [emptyPatch.status, extraPatch.status],
  );

  const acked = await call(analyst.jar, "PATCH", base, { body: { status: "acknowledged" } });
  check(
    "new -> acknowledged stamps acknowledged_at and takes the alert",
    acked.status === 200 &&
      acked.json.data.status === "acknowledged" &&
      !!acked.json.data.acknowledged_at &&
      acked.json.data.resolved_at === null &&
      acked.json.data.assigned_to === analystId,
    acked.json?.data,
  );
  const backToNew = await call(analyst.jar, "PATCH", base, { body: { status: "new" } });
  check(
    "an alert never goes back to new (409)",
    backToNew.status === 409 && code(backToNew) === "CONFLICT",
    backToNew.json,
  );
  const resolvedAlert = await call(analyst.jar, "PATCH", base, { body: { status: "resolved" } });
  check(
    "acknowledged -> resolved stamps resolved_at and keeps acknowledged_at",
    resolvedAlert.status === 200 &&
      !!resolvedAlert.json.data.resolved_at &&
      resolvedAlert.json.data.acknowledged_at === acked.json.data.acknowledged_at,
    resolvedAlert.json?.data,
  );
  const closedToAcked = await call(analyst.jar, "PATCH", base, {
    body: { status: "acknowledged" },
  });
  check(
    "a closed alert cannot become acknowledged (409)",
    closedToAcked.status === 409,
    closedToAcked.json,
  );
  const reopened = await call(analyst.jar, "PATCH", base, { body: { status: "investigating" } });
  check(
    "a closed alert can be reopened into investigating, which clears resolved_at",
    reopened.status === 200 &&
      reopened.json.data.status === "investigating" &&
      reopened.json.data.resolved_at === null,
    reopened.json?.data,
  );
  const falsePositive = await call(analyst.jar, "PATCH", base, {
    body: { status: "false_positive" },
  });
  check(
    "investigating -> false_positive closes it too",
    falsePositive.status === 200 && !!falsePositive.json.data.resolved_at,
    falsePositive.json,
  );
  const sameStatus = await call(analyst.jar, "PATCH", base, { body: { status: "false_positive" } });
  check(
    "asking for the status it already has changes nothing (200)",
    sameStatus.status === 200 && sameStatus.json.data.status === "false_positive",
    sameStatus.status,
  );
  const unassign = await call(analyst.jar, "PATCH", base, { body: { assigned_to: null } });
  check(
    "assigned_to null unassigns",
    unassign.status === 200 && unassign.json.data.assigned_to === null,
    unassign.json?.data,
  );
  const assignMe = await call(analyst.jar, "PATCH", base, { body: { assigned_to: "me" } });
  check(
    "assigned_to 'me' assigns the caller",
    assignMe.status === 200 && assignMe.json.data.assigned_to === analystId,
    assignMe.json?.data,
  );
  const assignViewer = await call(analyst.jar, "PATCH", base, { body: { assigned_to: viewerId } });
  check(
    "a viewer cannot be given an alert (422 on assigned_to)",
    assignViewer.status === 422 && problems(assignViewer).includes("assigned_to"),
    assignViewer.json,
  );
  const analystDeletes = await call(analyst.jar, "DELETE", base);
  check(
    "an analyst cannot delete an alert (403)",
    analystDeletes.status === 403,
    analystDeletes.json,
  );
  const afterAlertWork = await call(analyst.jar, "GET", base);
  check(
    "the alert still has its history fields after all that",
    afterAlertWork.json?.data?.status === "false_positive" &&
      !!afterAlertWork.json.data.acknowledged_at,
    afterAlertWork.json?.data?.status,
  );

  section("Investigations: read, search, filter, statistics");
  const anonInvestigations = await call(null, "GET", "/api/investigations");
  check(
    "GET /api/investigations without a session is 401",
    anonInvestigations.status === 401,
    anonInvestigations.status,
  );
  const investigationList = await call(viewer.jar, "GET", "/api/investigations");
  const investigationItems = investigationList.json?.data?.items ?? [];
  check(
    "viewer lists investigations with analyst, tags, provenance and counts",
    investigationList.status === 200 &&
      investigationItems.length > 0 &&
      investigationItems.every(
        (i) =>
          i.origin &&
          "analyst" in i &&
          Array.isArray(i.tags) &&
          typeof i.indicator_count === "number" &&
          typeof i.alert_count === "number",
      ),
    investigationList.json?.data?.pagination,
  );
  const investigationTotal = investigationList.json?.data?.pagination?.total ?? 0;
  const openOnes = await call(
    viewer.jar,
    "GET",
    "/api/investigations?status=investigating&priority=critical",
  );
  check(
    "status and priority filters combine",
    openOnes.json?.data?.items?.length > 0 &&
      openOnes.json.data.items.every(
        (i) => i.status === "investigating" && i.priority === "critical",
      ),
    openOnes.json?.data?.pagination,
  );
  const harborInvestigations = await call(viewer.jar, "GET", "/api/investigations?q=harbor");
  check(
    "search finds investigations by title or attached indicator value",
    harborInvestigations.json?.data?.items?.some((i) => /harbor/i.test(i.title)),
    harborInvestigations.json?.data?.items?.map((i) => i.title),
  );
  const investigationStats = await call(viewer.jar, "GET", "/api/investigations/stats");
  check(
    "statistics cover every status and add up to the total",
    investigationStats.json?.data?.by_status?.map((s) => s.status).join(",") ===
      "open,investigating,contained,resolved,closed" &&
      investigationStats.json.data.total === investigationTotal,
    investigationStats.json?.data,
  );
  const badInvestigationSort = await call(viewer.jar, "GET", "/api/investigations?sort=nope");
  check("an unknown sort is 422", badInvestigationSort.status === 422, badInvestigationSort.status);
  const detailOfDemo = await call(
    viewer.jar,
    "GET",
    `/api/investigations/${investigationItems.find((i) => /Harbor Lights C2/.test(i.title))?.id}`,
  );
  check(
    "a demo investigation opens with linked indicators, alerts, notes, evidence and a timeline",
    detailOfDemo.status === 200 &&
      detailOfDemo.json.data.indicators.length > 0 &&
      Array.isArray(detailOfDemo.json.data.alerts) &&
      Array.isArray(detailOfDemo.json.data.notes) &&
      detailOfDemo.json.data.timeline.at(-1)?.kind === "opened" &&
      detailOfDemo.json.data.origin === "demo",
    detailOfDemo.json?.data && Object.keys(detailOfDemo.json.data),
  );

  section("Investigations: lifecycle, notes, evidence, links");
  const viewerOpens = await call(viewer.jar, "POST", "/api/investigations", {
    body: { title: "Viewer case" },
  });
  check(
    "a viewer cannot open an investigation (403)",
    viewerOpens.status === 403,
    viewerOpens.json,
  );
  for (const [name, body] of [
    ["a status", { title: "x", status: "closed" }],
    ["an origin", { title: "x", origin: "external" }],
    ["an empty title", { title: " " }],
    ["a viewer as the analyst", { title: "x", analyst_id: viewerId }],
    ["an alert that does not exist", { title: "x", alert_ids: [NIL_UUID] }],
  ]) {
    const rejected = await call(analyst.jar, "POST", "/api/investigations", { body });
    check(
      `an investigation with ${name} is rejected (422)`,
      rejected.status === 422,
      rejected.json,
    );
  }

  // A fresh, untouched alert: opening an investigation on it should start work on it.
  const workAlert = await call(analyst.jar, "POST", "/api/alerts", {
    body: { title: `Smoke work alert ${stamp}` },
  });
  const workAlertId = workAlert.json?.data?.id;
  const madeInvestigation = await call(analyst.jar, "POST", "/api/investigations", {
    body: {
      title: `Smoke case ${stamp}`,
      description: "",
      priority: "high",
      tags: ["Smoke Case", "smoke case"],
      alert_ids: [workAlertId],
    },
  });
  const smokeCase = madeInvestigation.json?.data;
  check(
    "analyst opens an investigation (201): open, local, assigned to them, tags collapsed, alert attached",
    madeInvestigation.status === 201 &&
      smokeCase?.status === "open" &&
      smokeCase.origin === "local" &&
      smokeCase.analyst_id === analystId &&
      smokeCase.priority === "high" &&
      smokeCase.description === null &&
      smokeCase.tags.length === 1 &&
      smokeCase.alerts.length === 1,
    madeInvestigation.json,
  );
  const workedAlert = await call(analyst.jar, "GET", `/api/alerts/${workAlertId}`);
  check(
    "attaching the alert moved it from new to investigating and linked the investigation",
    workedAlert.json?.data?.status === "investigating" &&
      workedAlert.json.data.investigations.some((i) => i.id === smokeCase?.id),
    workedAlert.json?.data?.status,
  );
  const caseBase = `/api/investigations/${smokeCase?.id}`;

  const viewerNote = await call(viewer.jar, "POST", `${caseBase}/notes`, {
    body: { body: "nope" },
  });
  check("a viewer cannot write a note (403)", viewerNote.status === 403, viewerNote.json);
  const emptyNote = await call(analyst.jar, "POST", `${caseBase}/notes`, { body: { body: "   " } });
  const systemNote = await call(analyst.jar, "POST", `${caseBase}/notes`, {
    body: { body: "x", kind: "system" },
  });
  check(
    "an empty note, or one that claims to be system history, is 422",
    emptyNote.status === 422 && systemNote.status === 422,
    [emptyNote.status, systemNote.status],
  );
  const noted = await call(analyst.jar, "POST", `${caseBase}/notes`, {
    body: { body: "  Confirmed in the proxy logs.  " },
  });
  const ownNote = noted.json?.data?.notes?.find((n) => n.kind === "note");
  check(
    "analyst adds a note (201), trimmed and attributed to them",
    noted.status === 201 &&
      ownNote?.body === "Confirmed in the proxy logs." &&
      ownNote.author_id === analystId,
    noted.json?.data?.notes,
  );
  const editedNote = await call(analyst.jar, "PATCH", `${caseBase}/notes/${ownNote?.id}`, {
    body: { body: "Confirmed in the proxy and DNS logs." },
  });
  check(
    "the author edits their note",
    editedNote.status === 200 &&
      editedNote.json.data.notes.find((n) => n.id === ownNote.id)?.body.includes("DNS"),
    editedNote.json,
  );
  const adminEdits = await call(admin.jar, "PATCH", `${caseBase}/notes/${ownNote?.id}`, {
    body: { body: "Rewritten by an admin." },
  });
  check(
    "nobody else can edit somebody's note, not even an administrator (403)",
    adminEdits.status === 403,
    adminEdits.json,
  );

  const started = await call(analyst.jar, "PATCH", caseBase, { body: { status: "investigating" } });
  const historyLine = started.json?.data?.notes?.find((n) => n.kind === "system");
  check(
    "a status change leaves a system line in the history and the timeline",
    started.status === 200 &&
      /Status changed from Open to Investigating\./.test(historyLine?.body ?? "") &&
      started.json.data.timeline.some((e) => e.kind === "system" && e.title === historyLine.body),
    started.json?.data?.notes,
  );
  const editHistory = await call(analyst.jar, "PATCH", `${caseBase}/notes/${historyLine?.id}`, {
    body: { body: "forged" },
  });
  const deleteHistory = await call(admin.jar, "DELETE", `${caseBase}/notes/${historyLine?.id}`);
  check(
    "the status history cannot be edited or deleted by anyone (403)",
    editHistory.status === 403 && deleteHistory.status === 403,
    [editHistory.status, deleteHistory.status],
  );
  const forgedHistory = await call(analyst.jar, "PATCH", caseBase, {
    body: { status: "closed", closed_at: "2020-01-01T00:00:00.000Z" },
  });
  check(
    "closed_at is not the client's to set (422)",
    forgedHistory.status === 422,
    forgedHistory.json,
  );

  const closedCase = await call(analyst.jar, "PATCH", caseBase, { body: { status: "closed" } });
  check(
    "closing stamps closed_at",
    closedCase.status === 200 && !!closedCase.json.data.closed_at,
    closedCase.json?.data?.closed_at,
  );
  const reopenedCase = await call(analyst.jar, "PATCH", caseBase, {
    body: { status: "investigating", priority: "critical" },
  });
  check(
    "reopening clears closed_at, and a priority change is recorded too",
    reopenedCase.status === 200 &&
      reopenedCase.json.data.closed_at === null &&
      reopenedCase.json.data.notes.some((n) =>
        /Priority changed from High to Critical\./.test(n.body),
      ),
    reopenedCase.json?.data?.notes?.map((n) => n.body),
  );
  const unassignedCase = await call(analyst.jar, "PATCH", caseBase, { body: { analyst_id: null } });
  check(
    "the analyst can be removed, and it is recorded",
    unassignedCase.status === 200 &&
      unassignedCase.json.data.analyst_id === null &&
      unassignedCase.json.data.notes.some((n) => n.body === "Unassigned."),
    unassignedCase.json?.data?.analyst_id,
  );
  const viewerAnalyst = await call(analyst.jar, "PATCH", caseBase, {
    body: { analyst_id: viewerId },
  });
  check(
    "a viewer cannot be made the analyst (422)",
    viewerAnalyst.status === 422,
    viewerAnalyst.json,
  );

  const evidenceBody = { title: "Proxy export", location: "ticket #4711", description: "" };
  const viewerEvidence = await call(viewer.jar, "POST", `${caseBase}/evidence`, {
    body: evidenceBody,
  });
  check("a viewer cannot add evidence (403)", viewerEvidence.status === 403, viewerEvidence.json);
  const noLocation = await call(analyst.jar, "POST", `${caseBase}/evidence`, {
    body: { title: "x", location: " " },
  });
  check("evidence needs a location (422)", noLocation.status === 422, noLocation.json);
  const evidenceAdded = await call(analyst.jar, "POST", `${caseBase}/evidence`, {
    body: evidenceBody,
  });
  const evidence = evidenceAdded.json?.data?.evidence?.[0];
  check(
    "analyst adds evidence (201) that appears on the timeline",
    evidenceAdded.status === 201 &&
      evidence?.title === "Proxy export" &&
      evidence.description === null &&
      evidenceAdded.json.data.timeline.some((e) => e.kind === "evidence"),
    evidenceAdded.json?.data?.evidence,
  );

  // Two throwaway indicators, used here and in the linking checks below; removed at the end.
  const smokeIndicators = [];
  for (const suffix of ["a", "b"]) {
    const made = await call(analyst.jar, "POST", "/api/indicators", {
      body: { type: "domain", value: `smoke-p6-${suffix}-${stamp}.example` },
    });
    smokeIndicators.push(made.json?.data);
  }
  const [indA, indB] = smokeIndicators;
  const attached = await call(analyst.jar, "POST", `${caseBase}/indicators`, {
    body: { indicator_id: indA?.id },
  });
  check(
    "analyst attaches an indicator (201), shown with its provenance and on the timeline",
    attached.status === 201 &&
      attached.json.data.indicators.some((i) => i.id === indA?.id && i.origin === "local") &&
      attached.json.data.timeline.some((e) => e.kind === "indicator"),
    attached.json?.data?.indicators,
  );
  const attachedAgain = await call(analyst.jar, "POST", `${caseBase}/indicators`, {
    body: { indicator_id: indA?.id },
  });
  check("attaching it twice is refused (409)", attachedAgain.status === 409, attachedAgain.json);
  const ghostIndicator = await call(analyst.jar, "POST", `${caseBase}/indicators`, {
    body: { indicator_id: NIL_UUID },
  });
  check(
    "attaching an indicator that does not exist is refused (4xx, not 500)",
    ghostIndicator.status >= 400 && ghostIndicator.status < 500,
    ghostIndicator.json,
  );
  const detached = await call(analyst.jar, "DELETE", `${caseBase}/indicators/${indA?.id}`);
  check(
    "detaching removes only the link, and the indicator stays",
    detached.status === 200 &&
      (await call(analyst.jar, "GET", `/api/indicators/${indA?.id}`)).status === 200,
    detached.status,
  );
  const detachedAgain = await call(analyst.jar, "DELETE", `${caseBase}/indicators/${indA?.id}`);
  check(
    "detaching something that is not attached is 404",
    detachedAgain.status === 404,
    detachedAgain.status,
  );
  const detachAlert = await call(analyst.jar, "DELETE", `${caseBase}/alerts/${workAlertId}`);
  check(
    "an alert can be detached too",
    detachAlert.status === 200 && detachAlert.json.data.alerts.length === 0,
    detachAlert.json,
  );

  const evidenceGone = await call(analyst.jar, "DELETE", `${caseBase}/evidence/${evidence?.id}`);
  check(
    "evidence can be removed",
    evidenceGone.status === 200 && evidenceGone.json.data.evidence.length === 0,
    evidenceGone.json,
  );
  const adminDeletesNote = await call(admin.jar, "DELETE", `${caseBase}/notes/${ownNote?.id}`);
  check(
    "an administrator can remove somebody else's ordinary note",
    adminDeletesNote.status === 200 &&
      !adminDeletesNote.json.data.notes.some((n) => n.id === ownNote?.id),
    adminDeletesNote.json,
  );

  const analystDeletesCase = await call(analyst.jar, "DELETE", caseBase);
  const adminDeletesCase = await call(admin.jar, "DELETE", caseBase);
  const caseAfterDelete = await call(admin.jar, "GET", caseBase);
  check(
    "only an administrator deletes an investigation (403 for an analyst, 200, then 404)",
    analystDeletesCase.status === 403 &&
      adminDeletesCase.status === 200 &&
      caseAfterDelete.status === 404,
    [analystDeletesCase.status, adminDeletesCase.status, caseAfterDelete.status],
  );
  await adminRest("DELETE", "/rest/v1/tags?name=ilike.smoke*"); // the case's tag outlives the case
  const adminDeletesAlert = await call(admin.jar, "DELETE", base);
  const adminDeletesWorkAlert = await call(admin.jar, "DELETE", `/api/alerts/${workAlertId}`);
  const alertAfterDelete = await call(admin.jar, "GET", base);
  check(
    "an administrator deletes the alerts (200, then 404)",
    adminDeletesAlert.status === 200 &&
      adminDeletesWorkAlert.status === 200 &&
      alertAfterDelete.status === 404,
    [adminDeletesAlert.status, adminDeletesWorkAlert.status, alertAfterDelete.status],
  );

  section("MITRE ATT&CK matrix (catalog and technique pages)");
  const anonMatrix = await call(null, "GET", "/api/mitre");
  check("GET /api/mitre without a session is 401", anonMatrix.status === 401, anonMatrix.status);
  const matrix = await call(viewer.jar, "GET", "/api/mitre");
  const tactics = matrix.json?.data?.tactics ?? [];
  check(
    "the matrix has a column per tactic, each with techniques, and a summary",
    matrix.status === 200 &&
      tactics.length > 0 &&
      tactics.every((t) => t.name && Array.isArray(t.techniques) && t.techniques.length > 0) &&
      matrix.json.data.summary.total_techniques >= 10,
    matrix.json?.data?.summary,
  );
  const phishing = tactics.flatMap((t) => t.techniques).find((t) => t.id === "T1566");
  check(
    "a technique carries its name, a reference link and what alerts say about it (null when nothing)",
    phishing?.name === "Phishing" &&
      phishing.url?.startsWith("https://attack.mitre.org/") &&
      "observed" in phishing &&
      Array.isArray(phishing.subtechniques),
    phishing,
  );
  const observedOnly = await call(viewer.jar, "GET", "/api/mitre?observed=1");
  check(
    "observed=1 keeps only techniques an alert named",
    observedOnly.status === 200 &&
      observedOnly.json.data.tactics.every((t) =>
        t.techniques.every((c) => c.observed || c.subtechniques.some((s) => s.observed)),
      ),
    observedOnly.json?.data?.summary,
  );
  const badFlag = await call(viewer.jar, "GET", "/api/mitre?observed=maybe");
  check("an unknown observed flag is 422", badFlag.status === 422, badFlag.status);
  const technique = await call(viewer.jar, "GET", "/api/mitre/t1566");
  check(
    "a technique opens by id in either case, with its tactics, sub-techniques and alerts",
    technique.status === 200 &&
      technique.json.data.id === "T1566" &&
      Array.isArray(technique.json.data.tactics) &&
      Array.isArray(technique.json.data.subtechniques) &&
      Array.isArray(technique.json.data.alerts),
    technique.json,
  );
  const badTechnique = await call(viewer.jar, "GET", "/api/mitre/T9");
  const unknownTechnique = await call(viewer.jar, "GET", "/api/mitre/T9999");
  check(
    "a malformed or unknown technique id is 404",
    badTechnique.status === 404 && unknownTechnique.status === 404,
    [badTechnique.status, unknownTechnique.status],
  );
  const removed = await Promise.all(
    ["threat-actors", "campaigns", "malware"].map((name) =>
      call(viewer.jar, "GET", `/api/${name}`),
    ),
  );
  check(
    "threat actors, campaigns and malware are gone (404)",
    removed.every((r) => r.status === 404),
    removed.map((r) => r.status),
  );

  section("Indicators: relationships");
  const relBody = { target_id: indB?.id, relationship: "resolves_to" };
  const viewerRel = await call(viewer.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: relBody,
  });
  check("a viewer cannot relate indicators (403)", viewerRel.status === 403, viewerRel.json);
  const related = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: relBody,
  });
  const outgoing = related.json?.data?.relationships?.find((r) => r.other.id === indB?.id);
  check(
    "an analyst relates two indicators (201): outgoing from this one",
    related.status === 201 &&
      outgoing?.direction === "outgoing" &&
      outgoing.relationship === "resolves_to",
    related.json?.data?.relationships,
  );
  const otherSide = await call(analyst.jar, "GET", `/api/indicators/${indB?.id}`);
  check(
    "the other indicator shows it as incoming",
    otherSide.json?.data?.relationships?.some(
      (r) => r.direction === "incoming" && r.other.id === indA?.id,
    ),
    otherSide.json?.data?.relationships,
  );
  const sameRel = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: relBody,
  });
  const selfRel = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: { target_id: indA?.id, relationship: "related_to" },
  });
  const ghostRel = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: { target_id: NIL_UUID, relationship: "related_to" },
  });
  const badKind = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: { target_id: indB?.id, relationship: "likes" },
  });
  check(
    "the same relationship twice is 409; to itself, to nothing, or of an unknown kind is 422",
    sameRel.status === 409 &&
      selfRel.status === 422 &&
      ghostRel.status === 422 &&
      badKind.status === 422,
    [sameRel.status, selfRel.status, ghostRel.status, badKind.status],
  );
  const otherKind = await call(analyst.jar, "POST", `/api/indicators/${indA?.id}/relationships`, {
    body: { target_id: indB?.id, relationship: "related_to" },
  });
  check(
    "a different kind between the same two indicators is allowed",
    otherKind.status === 201,
    otherKind.json,
  );
  const relationshipId = outgoing?.id;
  const wrongIndicator = await call(
    analyst.jar,
    "DELETE",
    `/api/indicators/${NIL_UUID}/relationships/${relationshipId}`,
  );
  check(
    "a relationship cannot be removed through an indicator it does not involve (404)",
    wrongIndicator.status === 404,
    wrongIndicator.status,
  );
  const viewerUnrelate = await call(
    viewer.jar,
    "DELETE",
    `/api/indicators/${indA?.id}/relationships/${relationshipId}`,
  );
  check("a viewer cannot remove one (403)", viewerUnrelate.status === 403, viewerUnrelate.status);
  const unrelated = await call(
    analyst.jar,
    "DELETE",
    `/api/indicators/${indA?.id}/relationships/${relationshipId}`,
  );
  const unrelatedAgain = await call(
    analyst.jar,
    "DELETE",
    `/api/indicators/${indA?.id}/relationships/${relationshipId}`,
  );
  check(
    "an analyst removes it (200), and removing it again is 404",
    unrelated.status === 200 && unrelatedAgain.status === 404,
    [unrelated.status, unrelatedAgain.status],
  );

  for (const indicatorToRemove of smokeIndicators) {
    await call(admin.jar, "DELETE", `/api/indicators/${indicatorToRemove?.id}`);
  }

  section("Audit trail for alerts and investigations");
  // One query per action: the trail is newest-first and this section alone writes dozens of entries.
  const phase6Entries = [];
  for (const action of [
    "alert.created",
    "alert.status_changed",
    "alert.assigned",
    "alert.deleted",
    "investigation.created",
    "investigation.updated",
    "investigation.note_added",
    "investigation.note_updated",
    "investigation.note_deleted",
    "investigation.evidence_added",
    "investigation.evidence_removed",
    "investigation.link_added",
    "investigation.link_removed",
    "investigation.deleted",
    "indicator.relationship_added",
    "indicator.relationship_removed",
    "authz.denied",
  ]) {
    const logs = await call(admin.jar, "GET", `/api/audit-logs?action=${action}&page_size=100`);
    const items = logs.json?.data?.items ?? [];
    phase6Entries.push(...items);
    check(
      action === "authz.denied"
        ? "refused writes by viewers and analysts were recorded as denials"
        : `audit contains ${action}`,
      items.length > 0,
      logs.json?.data?.pagination,
    );
  }
  const attachedByWork = phase6Entries.find(
    (e) =>
      e.action === "alert.status_changed" && e.metadata?.reason === "attached to an investigation",
  );
  check(
    "the alert moved by attaching it to an investigation says why",
    !!attachedByWork && attachedByWork.metadata.to === "investigating",
    attachedByWork,
  );
  const phase6Trail = JSON.stringify(phase6Entries);
  check(
    "no note text, evidence locations or raw request bodies in the audit trail",
    !phase6Trail.includes("Confirmed in the proxy") && !phase6Trail.includes("ticket #4711"),
  );

  section("Global search: alerts, investigations and techniques");
  const wideSearch = await call(viewer.jar, "GET", "/api/search?q=harbor");
  const kinds = new Map((wideSearch.json?.data?.groups ?? []).map((g) => [g.kind, g]));
  check(
    "one search finds alerts and investigations, each linked and labelled with its origin",
    ["alert", "investigation"].every((kind) => kinds.get(kind)?.hits?.length > 0) &&
      kinds.get("investigation").hits[0].href.startsWith("/investigations/") &&
      kinds.get("alert").hits[0].href.startsWith("/alerts/") &&
      !kinds.has("threat_actor") &&
      !kinds.has("campaign") &&
      !kinds.has("malware"),
    [...kinds.keys()],
  );
  const techniqueSearch = await call(viewer.jar, "GET", "/api/search?q=T1566");
  const techniqueHit = techniqueSearch.json?.data?.groups?.find((g) => g.kind === "technique")
    ?.hits?.[0];
  check(
    "a technique id finds the technique, without a made-up origin",
    techniqueHit?.href === "/mitre/T1566" && techniqueHit.origin === null,
    techniqueHit,
  );

  // ---------------------------------------------------------------------------------------------
  // Phase 6b: API keys and telemetry ingestion
  // ---------------------------------------------------------------------------------------------
  // Everything created here carries a marker (manager "smoke-manager", agent ids "smoke-...") so the
  // clean-up at the end removes only this run's data, never a real sensor's.
  const marker = `smoke-${stamp}`;
  const keyPattern = /^arc_[A-Za-z0-9_-]{43}$/;
  const ingestUrl = "/api/ingest/wazuh";
  const bearer = (token) => ({ authorization: `Bearer ${token}` });
  const wazuhAlert = (n, overrides = {}) => ({
    id: `${stamp}.${n}`,
    timestamp: new Date(Date.now() - (10 - n) * 1000).toISOString().replace("Z", "+0000"),
    rule: {
      id: "60204",
      level: 10,
      description: `Smoke alert ${n}`,
      groups: ["windows", "authentication_failures"],
    },
    agent: { id: marker, name: `SMOKE-WIN10-${stamp}`, ip: "192.168.56.150" },
    manager: { name: "smoke-manager" },
    full_log: "smoke log line",
    data: { win: { eventdata: { ipAddress: "198.51.100.199" } } },
    location: "EventChannel",
    ...overrides,
  });
  const smokeSha = createHash("sha256").update(marker).digest("hex");
  const smokeAlerts = [
    wazuhAlert(1, {
      rule: {
        id: "60204",
        level: 10,
        description: `Smoke logon failures ${stamp}`,
        groups: ["authentication_failures"],
        mitre: { id: ["T1110"] },
      },
    }),
    wazuhAlert(2, {
      rule: {
        id: "100210",
        level: 12,
        description: `Smoke certutil ${stamp}`,
        groups: ["sysmon", "sysmon_event1"],
        mitre: { id: ["T1059.001"] },
      },
      data: {
        win: {
          system: { providerName: "Microsoft-Windows-Sysmon", eventID: "1" },
          eventdata: { hashes: `SHA256=${smokeSha}`, queryName: `${marker}.example` },
        },
      },
    }),
    wazuhAlert(3, {
      rule: {
        id: "60106",
        level: 3,
        description: `Smoke routine ${stamp}`,
        groups: ["authentication_success"],
      },
      data: { win: { eventdata: { ipAddress: "198.51.100.198" } } },
    }),
  ];

  section("API keys: who may make one, what is shown");
  const anonKeys = await call(null, "GET", "/api/api-keys");
  const viewerKeys = await call(viewer.jar, "GET", "/api/api-keys");
  check(
    "keys need a session (401) and a role that may manage them (viewers: 403)",
    anonKeys.status === 401 && viewerKeys.status === 403,
    [anonKeys.status, viewerKeys.status],
  );
  const analystKey = await call(analyst.jar, "POST", "/api/api-keys", {
    body: { name: "Smoke analyst key", scopes: ["ingest:wazuh"] },
  });
  check(
    "an analyst cannot make an ingest key (403): the scope needs events:write",
    analystKey.status === 403 && code(analystKey) === "FORBIDDEN",
    analystKey.json,
  );
  for (const [name, body] of [
    ["no name", { name: "  ", scopes: ["ingest:wazuh"] }],
    ["no scope", { name: "x", scopes: [] }],
    ["an unknown scope", { name: "x", scopes: ["admin:everything"] }],
    ["a lifetime over a year", { name: "x", scopes: ["ingest:wazuh"], expires_in_days: 366 }],
    ["an owner", { name: "x", scopes: ["ingest:wazuh"], user_id: analystId }],
    ["a hash of its own", { name: "x", scopes: ["ingest:wazuh"], key_hash: "a".repeat(64) }],
  ]) {
    const rejected = await call(admin.jar, "POST", "/api/api-keys", { body });
    check(`a key request with ${name} is rejected (422)`, rejected.status === 422, rejected.json);
  }
  const madeKey = await call(admin.jar, "POST", "/api/api-keys", {
    body: {
      name: `Smoke key ${stamp}`,
      scopes: ["ingest:wazuh", "ingest:wazuh"],
      expires_in_days: 7,
    },
  });
  const ingestKey = madeKey.json?.data?.key;
  const keyInfo = madeKey.json?.data?.api_key;
  check(
    "an administrator gets a key (201), shown once, with its details but never the hash",
    madeKey.status === 201 &&
      keyPattern.test(ingestKey ?? "") &&
      keyInfo?.status === "active" &&
      keyInfo.scopes.join() === "ingest:wazuh" &&
      keyInfo.key_prefix === ingestKey.slice(0, 8) &&
      !("key_hash" in keyInfo),
    madeKey.json?.data && Object.keys(madeKey.json.data),
  );
  check(
    "the key expires in the 7 days asked for",
    Math.abs(Date.parse(keyInfo?.expires_at) - (Date.now() + 7 * 86400_000)) < 120_000,
    keyInfo?.expires_at,
  );
  const adminKeys = await call(admin.jar, "GET", "/api/api-keys");
  const analystKeys = await call(analyst.jar, "GET", "/api/api-keys");
  check(
    "the list shows the key without its secret; an analyst does not see an administrator's keys",
    adminKeys.json?.data?.some((k) => k.id === keyInfo?.id) &&
      !JSON.stringify(adminKeys.json?.data).includes(ingestKey) &&
      !JSON.stringify(adminKeys.json?.data).includes("key_hash") &&
      analystKeys.status === 200 &&
      !analystKeys.json.data.some((k) => k.id === keyInfo?.id),
    [adminKeys.status, analystKeys.status],
  );
  const analystRevokes = await call(analyst.jar, "DELETE", `/api/api-keys/${keyInfo?.id}`);
  check(
    "an analyst cannot revoke somebody else's key (404: it is not theirs to see)",
    analystRevokes.status === 404,
    analystRevokes.status,
  );

  section("Ingest: the key is the only way in");
  const noKey = await call(null, "POST", ingestUrl, { body: { alerts: [smokeAlerts[0]] } });
  const badKey = await call(null, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[0]] },
    headers: bearer("arc_" + "x".repeat(43)),
  });
  const junkKey = await call(null, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[0]] },
    headers: bearer("not-a-key"),
  });
  check(
    "no key, a made-up key and a malformed one all get the same 401, with a Bearer challenge",
    noKey.status === 401 &&
      badKey.status === 401 &&
      junkKey.status === 401 &&
      noKey.text === badKey.text &&
      badKey.text === junkKey.text &&
      /^Bearer/.test(noKey.headers.get("www-authenticate") ?? ""),
    [noKey.status, badKey.status, junkKey.status, noKey.headers.get("www-authenticate")],
  );
  const sessionOnly = await call(admin.jar, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[0]] },
  });
  check(
    "a signed-in administrator's session is not a key (401)",
    sessionOnly.status === 401,
    sessionOnly.status,
  );
  const viaGet = await call(null, "GET", ingestUrl);
  check(
    "the ingest endpoint takes POST only",
    viaGet.status === 405 || viaGet.status === 404,
    viaGet.status,
  );
  const nothingWritten = await call(admin.jar, "GET", `/api/events?source=wazuh&page_size=1`);
  check(
    "and nothing was written by any of those",
    (nothingWritten.json?.data?.items ?? []).every((e) => !String(e.title).includes(String(stamp))),
    nothingWritten.json?.data?.pagination,
  );

  section("Ingest: a batch of Wazuh alerts");
  const sent = await call(null, "POST", ingestUrl, {
    body: { alerts: [...smokeAlerts, "junk", { rule: {} }] },
    headers: bearer(ingestKey),
  });
  const summary = sent.json?.data;
  check(
    "a batch is recorded: 3 events, alerts for level 7 and up only, one asset, indicators, and two alerts rejected on their own",
    sent.status === 200 &&
      summary?.received === 5 &&
      summary.events_created === 3 &&
      summary.alerts_created === 2 &&
      summary.assets_created === 1 &&
      summary.indicators_created === 3 &&
      summary.duplicates === 0 &&
      summary.rejected?.map((r) => r.index).join() === "3,4" &&
      /Not a Wazuh alert/.test(summary.rejected[0].reason),
    summary,
  );
  check(
    "the answer never echoes the key or the alerts",
    !sent.text.includes(ingestKey) && !sent.text.includes("smoke log line"),
  );
  const resent = await call(null, "POST", ingestUrl, {
    body: { alerts: smokeAlerts },
    headers: bearer(ingestKey),
  });
  check(
    "sending the same alerts again is harmless: all duplicates, nothing created",
    resent.status === 200 &&
      resent.json?.data?.duplicates === 3 &&
      resent.json.data.events_created === 0 &&
      resent.json.data.alerts_created === 0 &&
      resent.json.data.assets_created === 0 &&
      resent.json.data.indicators_created === 0,
    resent.json?.data,
  );
  const alone = await call(null, "POST", ingestUrl, {
    body: { alerts: ["junk"] },
    headers: bearer(ingestKey),
  });
  check(
    "a batch with nothing usable is answered (200), with every alert rejected and nothing stored",
    alone.status === 200 &&
      alone.json?.data?.rejected?.length === 1 &&
      alone.json.data.events_created === 0,
    alone.json?.data,
  );
  for (const [name, request, status] of [
    [
      "not JSON",
      { body: "{oops", headers: { ...bearer(ingestKey), "content-type": "application/json" } },
      400,
    ],
    [
      "not declared as JSON",
      { body: "alerts=1", headers: { ...bearer(ingestKey), "content-type": "text/plain" } },
      415,
    ],
    ["an empty list", { body: { alerts: [] }, headers: bearer(ingestKey) }, 422],
    [
      "101 alerts",
      { body: { alerts: Array(101).fill(smokeAlerts[2]) }, headers: bearer(ingestKey) },
      422,
    ],
    [
      "a field it does not know",
      { body: { alerts: [smokeAlerts[2]], extra: 1 }, headers: bearer(ingestKey) },
      422,
    ],
  ]) {
    const refused = await call(null, "POST", ingestUrl, request);
    check(`a request with ${name} is refused (${status})`, refused.status === status, [
      refused.status,
      refused.json?.error,
    ]);
  }
  const huge = await call(null, "POST", ingestUrl, {
    body: JSON.stringify({ alerts: [{ full_log: "x".repeat(1024 * 1024 + 100) }] }),
    headers: bearer(ingestKey),
  });
  check("a body over 1 MiB is refused (413)", huge.status === 413, huge.status);
  const bigAlert = await call(null, "POST", ingestUrl, {
    body: {
      alerts: [
        wazuhAlert(4, {
          rule: { id: "1", level: 8, description: `Smoke big ${stamp}` },
          full_log: "L".repeat(200_000),
          data: { blob: "D".repeat(200_000) },
        }),
      ],
    },
    headers: bearer(ingestKey),
  });
  check(
    "a large alert is accepted and stored within its limit",
    bigAlert.status === 200 && bigAlert.json?.data?.events_created === 1,
    bigAlert.json,
  );

  section("Ingest: what it created, as people see it");
  const wazuhAlerts = await call(
    viewer.jar,
    "GET",
    `/api/alerts?source=wazuh&q=${encodeURIComponent(`SMOKE-WIN10-${stamp}`)}`,
  );
  const ingestedAlert = wazuhAlerts.json?.data?.items?.find(
    (a) => a.title === `Smoke logon failures ${stamp}`,
  );
  check(
    "the alerts are searchable by their asset, and are external, new, unassigned, high",
    wazuhAlerts.json?.data?.pagination?.total === 3 &&
      ingestedAlert?.origin === "external" &&
      ingestedAlert.source === "wazuh" &&
      ingestedAlert.status === "new" &&
      ingestedAlert.assigned_to === null &&
      ingestedAlert.severity === "high" &&
      ingestedAlert.asset?.name === `SMOKE-WIN10-${stamp}`,
    wazuhAlerts.json?.data?.items?.map((a) => a.title),
  );
  const alertDetail = await call(viewer.jar, "GET", `/api/alerts/${ingestedAlert?.id}`);
  const ingestedDetail = alertDetail.json?.data;
  check(
    "an alert opens with its machine, the attacker's address as its indicator, ATT&CK techniques (named when the workspace knows them) and the raw event",
    alertDetail.status === 200 &&
      ingestedDetail?.asset?.ip_address === "192.168.56.150" &&
      ingestedDetail.asset.os === "Windows" &&
      ingestedDetail.indicator?.value === "198.51.100.199" &&
      ingestedDetail.indicator.verdict === "unknown" &&
      ingestedDetail.techniques?.[0]?.id === "T1110" &&
      ingestedDetail.techniques[0].name === "Brute Force" &&
      ingestedDetail.event?.payload?.rule?.id === "60204" &&
      ingestedDetail.event.payload.full_log === "smoke log line" &&
      ingestedDetail.event.source === "wazuh",
    ingestedDetail && {
      asset: ingestedDetail.asset,
      indicator: ingestedDetail.indicator,
      techniques: ingestedDetail.techniques,
    },
  );
  const techniqueAlert = wazuhAlerts.json?.data?.items?.find(
    (a) => a.title === `Smoke certutil ${stamp}`,
  );
  const techniqueDetail = await call(viewer.jar, "GET", `/api/alerts/${techniqueAlert?.id}`);
  check(
    "a technique the workspace does not know is kept without a name (no invented link)",
    techniqueDetail.json?.data?.techniques?.[0]?.id === "T1059.001" &&
      techniqueDetail.json.data.techniques[0].name === null,
    techniqueDetail.json?.data?.techniques,
  );
  const seenMatrix = await call(viewer.jar, "GET", "/api/mitre?observed=1");
  const seenColumn = seenMatrix.json?.data?.tactics?.find((t) =>
    t.techniques.some((c) => c.id === "T1110"),
  );
  const seenBrute = seenColumn?.techniques.find((c) => c.id === "T1110");
  check(
    "a technique the ingested alerts named is highlighted on the matrix, under its tactic, with a count",
    seenColumn?.name === "Credential Access" &&
      seenBrute?.observed?.alert_count >= 1 &&
      ["low", "medium", "high", "critical", "info"].includes(seenBrute.observed.max_severity) &&
      seenMatrix.json.data.summary.observed_techniques >= 1,
    seenBrute,
  );
  const byTechnique = await call(viewer.jar, "GET", "/api/alerts?technique=t1110&page_size=100");
  check(
    "the alert list filters by technique (any case), and only those alerts come back",
    byTechnique.status === 200 &&
      byTechnique.json.data.items.length >= 1 &&
      byTechnique.json.data.items.every((a) => a.technique_ids.includes("T1110")),
    byTechnique.json?.data?.pagination,
  );
  const badTechniqueFilter = await call(viewer.jar, "GET", "/api/alerts?technique=nope");
  check(
    "a malformed technique filter is 422",
    badTechniqueFilter.status === 422,
    badTechniqueFilter.status,
  );
  const bruteDetail = await call(viewer.jar, "GET", "/api/mitre/T1110");
  check(
    "the technique page lists the alerts that name it, and how many there are",
    bruteDetail.status === 200 &&
      bruteDetail.json.data.alert_total >= 1 &&
      bruteDetail.json.data.alerts.length >= 1 &&
      bruteDetail.json.data.observed?.alert_count >= 1,
    bruteDetail.json?.data && { total: bruteDetail.json.data.alert_total },
  );
  const ipIndicator = await call(viewer.jar, "GET", `/api/indicators?q=198.51.100.199`);
  const noiseIndicator = await call(viewer.jar, "GET", `/api/indicators?q=198.51.100.198`);
  check(
    "indicators from alerts are external, source wazuh, verdict unknown (a sensor sighting is not a verdict); the routine level-3 alert's address created none",
    ipIndicator.json?.data?.items?.[0]?.origin === "external" &&
      ipIndicator.json.data.items[0].verdict === "unknown" &&
      ipIndicator.json.data.items[0].source === "wazuh" &&
      noiseIndicator.json?.data?.pagination?.total === 0,
    [ipIndicator.json?.data?.items?.[0], noiseIndicator.json?.data?.pagination],
  );
  const smokeHash = await call(viewer.jar, "GET", `/api/indicators?q=${smokeSha}`);
  const smokeDomain = await call(viewer.jar, "GET", `/api/indicators?q=${marker}.example`);
  check(
    "the hash and the queried name of the second alert are indicators too",
    smokeHash.json?.data?.pagination?.total === 1 &&
      smokeDomain.json?.data?.pagination?.total === 1,
    [smokeHash.json?.data?.pagination, smokeDomain.json?.data?.pagination],
  );

  const events = await call(viewer.jar, "GET", `/api/events?source=wazuh&origin=external`);
  const ourEvents = (events.json?.data?.items ?? []).filter((e) =>
    String(e.title).includes(String(stamp)),
  );
  check(
    "events list newest first with their asset, and the ones that raised an alert say so",
    events.status === 200 &&
      ourEvents.length >= 3 &&
      ourEvents.every((e) => e.origin === "external" && e.source === "wazuh") &&
      ourEvents.some((e) => e.alert_id !== null) &&
      ourEvents.some((e) => e.alert_id === null && e.severity === "info") &&
      (events.json.data.items ?? [])
        .map((e) => e.occurred_at)
        .every((t, i, all) => i === 0 || all[i - 1] >= t),
    ourEvents.map((e) => [e.title, e.alert_id !== null]),
  );
  const severityFilter = await call(viewer.jar, "GET", `/api/events?source=wazuh&severity=high`);
  const badEventQuery = await call(viewer.jar, "GET", `/api/events?sort=title`);
  const eventsPastEnd = await call(viewer.jar, "GET", `/api/events?page=9999`);
  check(
    "event filters work, a bad sort is 422 and a page past the end is an empty page",
    severityFilter.json?.data?.items?.every((e) => e.severity === "high") &&
      badEventQuery.status === 422 &&
      eventsPastEnd.status === 200 &&
      eventsPastEnd.json?.data?.items?.length === 0 &&
      eventsPastEnd.json.data.pagination.total > 0,
    [severityFilter.status, badEventQuery.status, eventsPastEnd.status],
  );
  const assets = await call(viewer.jar, "GET", `/api/assets?source=wazuh`);
  const ourAsset = assets.json?.data?.items?.find((a) => a.external_id === marker);
  check(
    "the machine is an asset: external, with its address, and no operating system guess beyond the Windows data it sent",
    assets.status === 200 &&
      ourAsset?.origin === "external" &&
      ourAsset.ip_address === "192.168.56.150" &&
      ourAsset.os === "Windows" &&
      ourAsset.name === `SMOKE-WIN10-${stamp}`,
    ourAsset,
  );
  const sources = await call(viewer.jar, "GET", "/api/telemetry/sources");
  const wazuhCard = sources.json?.data?.find((s) => s.id === "wazuh" && s.origin === "external");
  const demoCards = sources.json?.data?.filter((s) => s.origin === "demo") ?? [];
  check(
    "the source list says Wazuh is receiving (something arrived just now), lists the demo feeds as demo, and lists Wazuh first",
    sources.status === 200 &&
      sources.json.data[0].id === "wazuh" &&
      wazuhCard?.status === "receiving" &&
      wazuhCard.events_total >= 3 &&
      wazuhCard.assets_total >= 1 &&
      demoCards.length >= 3 &&
      demoCards.every((c) => c.status === "demo"),
    sources.json?.data?.map((s) => `${s.id}:${s.status}`),
  );
  const anonEvents = await call(null, "GET", "/api/events");
  const anonAssets = await call(null, "GET", "/api/assets");
  check(
    "events, assets and sources need a session (401)",
    anonEvents.status === 401 && anonAssets.status === 401,
    [anonEvents.status, anonAssets.status],
  );

  const analystWorks = await call(analyst.jar, "PATCH", `/api/alerts/${ingestedAlert?.id}`, {
    body: { status: "acknowledged" },
  });
  check(
    "an ingested alert follows the same lifecycle as any other (acknowledge: 200)",
    analystWorks.status === 200 &&
      analystWorks.json?.data?.status === "acknowledged" &&
      analystWorks.json.data.assigned_to === analystId,
    analystWorks.json?.data?.status,
  );
  const analystForges = await call(analyst.jar, "POST", "/api/alerts", {
    body: { title: "Forged", source: "wazuh", origin: "external" },
  });
  check(
    "nobody can forge sensor data through the alert API (422)",
    analystForges.status === 422,
    analystForges.status,
  );

  section("Ingest: the audit trail, and revoking the key");
  const batchLogs = await call(
    admin.jar,
    "GET",
    "/api/audit-logs?action=ingest.batch&page_size=50",
  );
  const ourBatch = batchLogs.json?.data?.items?.find(
    (e) => e.entity_id === keyInfo?.id && e.metadata?.events_created === 3,
  );
  const allBatches = JSON.stringify(
    batchLogs.json?.data?.items?.filter((e) => e.entity_id === keyInfo?.id) ?? [],
  );
  check(
    "each accepted batch is one audit entry: which key, how many of each outcome",
    ourBatch?.metadata?.source === "wazuh" &&
      ourBatch.metadata.key_prefix === keyInfo?.key_prefix &&
      ourBatch.metadata.accepted === 3 &&
      ourBatch.metadata.rejected === 2 &&
      ourBatch.metadata.alerts_created === 2,
    ourBatch?.metadata,
  );
  check(
    "and nothing of the alerts or the key is in it",
    !allBatches.includes(ingestKey) &&
      !allBatches.includes("smoke log line") &&
      !allBatches.includes("198.51.100.199") &&
      !allBatches.includes(`SMOKE-WIN10-${stamp}`),
  );
  const keyLogs = await call(
    admin.jar,
    "GET",
    "/api/audit-logs?action=api_key.created&page_size=20",
  );
  const createdLog = keyLogs.json?.data?.items?.find((e) => e.entity_id === keyInfo?.id);
  check(
    "creating the key is audited without the key",
    createdLog?.metadata?.name === `Smoke key ${stamp}` &&
      !JSON.stringify(createdLog).includes(ingestKey),
    createdLog?.metadata,
  );
  const deniedIngest = await call(admin.jar, "GET", `/api/api-keys`);
  check(
    "the key was recorded as used",
    deniedIngest.json?.data?.find((k) => k.id === keyInfo?.id)?.last_used_at !== null,
    deniedIngest.json?.data?.find((k) => k.id === keyInfo?.id)?.last_used_at,
  );

  const expiring = await adminRest("PATCH", `/rest/v1/api_keys?id=eq.${keyInfo?.id}`, {
    expires_at: new Date(Date.now() - 1000).toISOString(),
  });
  const expiredTry = await call(null, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[2]] },
    headers: bearer(ingestKey),
  });
  const expiredList = await call(admin.jar, "GET", "/api/api-keys");
  check(
    "(setup) the key was made to expire, and an expired key is refused (401, same as any other bad key)",
    expiring.status === 204 &&
      expiredTry.status === 401 &&
      expiredTry.text === noKey.text &&
      expiredList.json?.data?.find((k) => k.id === keyInfo?.id)?.status === "expired",
    [expiring.status, expiredTry.status],
  );
  await adminRest("PATCH", `/rest/v1/api_keys?id=eq.${keyInfo?.id}`, {
    expires_at: new Date(Date.now() + 86400_000).toISOString(),
  });
  const alive = await call(null, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[2]] },
    headers: bearer(ingestKey),
  });
  check("(setup) with a future expiry it works again", alive.status === 200, alive.status);

  const revoked = await call(admin.jar, "DELETE", `/api/api-keys/${keyInfo?.id}`);
  const afterRevoke = await call(null, "POST", ingestUrl, {
    body: { alerts: [smokeAlerts[2]] },
    headers: bearer(ingestKey),
  });
  const revokedAgain = await call(admin.jar, "DELETE", `/api/api-keys/${keyInfo?.id}`);
  const unknownRevoke = await call(admin.jar, "DELETE", `/api/api-keys/${NIL_UUID}`);
  check(
    "revoking stops the key at once (401), revoking again is harmless (200) and an unknown key is 404",
    revoked.status === 200 &&
      revoked.json?.data?.status === "revoked" &&
      afterRevoke.status === 401 &&
      afterRevoke.text === noKey.text &&
      revokedAgain.status === 200 &&
      unknownRevoke.status === 404,
    [revoked.status, afterRevoke.status, revokedAgain.status, unknownRevoke.status],
  );
  const revokeLogs = await call(
    admin.jar,
    "GET",
    "/api/audit-logs?action=api_key.revoked&page_size=20",
  );
  const revokedEntries = (revokeLogs.json?.data?.items ?? []).filter(
    (e) => e.entity_id === keyInfo?.id,
  );
  check("revoking is audited once, not twice", revokedEntries.length === 1, revokedEntries.length);

  // Clean-up: only what this run created.
  await adminRest("DELETE", `/rest/v1/alerts?source_event_id=like.smoke-manager:*`);
  await adminRest("DELETE", `/rest/v1/events?source_event_id=like.smoke-manager:*`);
  await adminRest("DELETE", `/rest/v1/assets?external_id=eq.${marker}`);
  await adminRest(
    "DELETE",
    `/rest/v1/indicators?value=in.(198.51.100.199,${smokeSha},${marker}.example)`,
  );
  await adminRest("DELETE", `/rest/v1/api_keys?id=eq.${keyInfo?.id}`);
  const leftovers = await call(
    viewer.jar,
    "GET",
    `/api/alerts?source=wazuh&q=${encodeURIComponent(`SMOKE-WIN10-${stamp}`)}`,
  );
  check(
    "(cleanup) the smoke run's telemetry data is removed again",
    leftovers.json?.data?.pagination?.total === 0,
    leftovers.json?.data?.pagination,
  );

  section("Dashboard");
  {
    const overview = await call(viewer.jar, "GET", "/api/dashboard");
    check("a viewer can read the dashboard (200)", overview.status === 200, overview.json?.error);
    const counts = overview.json?.data?.counts;
    check(
      "it has real, non-negative counts and the standard shape",
      counts && Object.values(counts).every((n) => typeof n === "number" && n >= 0),
      counts,
    );
    check(
      "it has a severity, IOC type and verdict distribution",
      Array.isArray(overview.json?.data?.severity_distribution) &&
        Array.isArray(overview.json?.data?.ioc_distribution) &&
        Array.isArray(overview.json?.data?.verdict_distribution),
    );
    const windowed = await call(viewer.jar, "GET", "/api/dashboard?days=30&severity=high");
    check(
      "the days window is honoured by the activity series",
      windowed.json?.data?.activity?.length === 30,
      windowed.json?.data?.activity?.length,
    );
    const badDays = await call(viewer.jar, "GET", "/api/dashboard?days=0");
    check("an out-of-range window is 422", badDays.status === 422, badDays.json);
    const badSeverity = await call(viewer.jar, "GET", "/api/dashboard?severity=urgent");
    check("an unknown severity is 422", badSeverity.status === 422, badSeverity.json);
  }

  section("Reports");
  const reportIds = [];
  {
    const deniedCreate = await call(viewer.jar, "POST", "/api/reports", {
      body: { type: "alerts" },
    });
    check(
      "a viewer cannot generate a report (403)",
      deniedCreate.status === 403,
      deniedCreate.json,
    );

    const alerts = await call(analyst.jar, "POST", "/api/reports", {
      body: { type: "alerts", title: `smoke-${stamp} alert summary` },
    });
    check("an analyst generates an alert summary (201)", alerts.status === 201, alerts.json?.error);
    check(
      "its content has the workspace's real totals",
      typeof alerts.json?.data?.content?.total === "number" &&
        alerts.json.data.content.total > 0 &&
        alerts.json.data.origin === "local",
      alerts.json?.data,
    );
    if (alerts.json?.data?.id) reportIds.push(alerts.json.data.id);

    const noTitle = await call(analyst.jar, "POST", "/api/reports", {
      body: { type: "indicators" },
    });
    check(
      "a report without a title gets a generated one",
      noTitle.status === 201 &&
        typeof noTitle.json?.data?.title === "string" &&
        noTitle.json.data.title.length > 0,
      noTitle.json?.data?.title,
    );
    if (noTitle.json?.data?.id) reportIds.push(noTitle.json.data.id);

    const missingTarget = await call(analyst.jar, "POST", "/api/reports", {
      body: { type: "investigation" },
    });
    check(
      "an investigation report without an id is 422",
      missingTarget.status === 422,
      missingTarget.json,
    );

    const found = await call(
      analyst.jar,
      "GET",
      "/api/investigations?q=Harbor%20Lights&page_size=1",
    );
    const investigationId = found.json?.data?.items?.[0]?.id;
    if (investigationId) {
      const investigationReport = await call(analyst.jar, "POST", "/api/reports", {
        body: { type: "investigation", investigation_id: investigationId },
      });
      check(
        "an investigation report embeds its notes and linked records",
        investigationReport.status === 201 &&
          Array.isArray(investigationReport.json?.data?.content?.notes) &&
          investigationReport.json.data.investigation_id === investigationId,
        investigationReport.json?.data,
      );
      if (investigationReport.json?.data?.id) reportIds.push(investigationReport.json.data.id);
    }
    check("(setup) found the Harbor Lights investigation", !!investigationId);

    const list = await call(
      analyst.jar,
      "GET",
      `/api/reports?q=${encodeURIComponent(`smoke-${stamp}`)}`,
    );
    check(
      "the search finds the titled report by title",
      list.json?.data?.pagination?.total === 1,
      list.json?.data,
    );
    const byType = await call(analyst.jar, "GET", "/api/reports?type=alerts&page_size=1");
    check(
      "the type filter narrows the list",
      (byType.json?.data?.items ?? []).every((r) => r.type === "alerts"),
      byType.json?.data,
    );

    const viewerRead = await call(viewer.jar, "GET", `/api/reports/${reportIds[0]}`);
    check(
      "a viewer can read a report someone else made (200)",
      viewerRead.status === 200,
      viewerRead.json?.error,
    );
    const missing = await call(
      viewer.jar,
      "GET",
      "/api/reports/00000000-0000-4000-8000-000000000000",
    );
    check("an unknown report id is 404", missing.status === 404, missing.json);

    const deniedDelete = await call(viewer.jar, "DELETE", `/api/reports/${reportIds[0]}`);
    check("a viewer cannot delete a report (403)", deniedDelete.status === 403, deniedDelete.json);
    const deleted = await call(analyst.jar, "DELETE", `/api/reports/${reportIds[0]}`);
    check(
      "reports:write deletes a report (even one it did not create)",
      deleted.status === 200,
      deleted.json,
    );
    const goneNow = await call(viewer.jar, "GET", `/api/reports/${reportIds[0]}`);
    check("it is gone afterwards (404)", goneNow.status === 404, goneNow.json);
    reportIds.shift();

    // Clean up the other reports this run generated (their own delete rule was already checked above).
    for (const id of reportIds) await call(analyst.jar, "DELETE", `/api/reports/${id}`);
    const stillThere = [];
    for (const id of reportIds) {
      const probe = await call(admin.jar, "GET", `/api/reports/${id}`);
      if (probe.status !== 404) stillThere.push(id);
    }
    check("(cleanup) no reports from this run remain", stillThere.length === 0, stillThere);
  }

  section("Integrations");
  {
    const deniedRead = await call(viewer.jar, "GET", "/api/integrations");
    check(
      "a viewer cannot read the integrations catalog (403)",
      deniedRead.status === 403,
      deniedRead.json,
    );
    const list = await call(analyst.jar, "GET", "/api/integrations");
    check(
      "an analyst reads the catalog, without any key values",
      list.status === 200 &&
        Array.isArray(list.json?.data) &&
        !JSON.stringify(list.json.data).match(/[A-Za-z0-9_-]{32,}/),
      list.status,
    );
    const demoRow = list.json?.data?.find((r) => r.provider === "demo");
    check(
      "the demo provider is always configured and enabled",
      demoRow?.configured && demoRow?.enabled,
      demoRow,
    );

    const analystToggle = await call(analyst.jar, "PATCH", "/api/integrations/virustotal", {
      body: { enabled: false },
    });
    check(
      "an analyst cannot toggle a provider (403)",
      analystToggle.status === 403,
      analystToggle.json,
    );
    const demoOff = await call(admin.jar, "PATCH", "/api/integrations/demo", {
      body: { enabled: false },
    });
    check(
      "the demo provider cannot be turned off, even by an admin (409)",
      demoOff.status === 409,
      demoOff.json,
    );
    const unknown = await call(admin.jar, "PATCH", "/api/integrations/not-a-provider", {
      body: { enabled: false },
    });
    check("an unknown provider is 404", unknown.status === 404, unknown.json);

    const off = await call(admin.jar, "PATCH", "/api/integrations/virustotal", {
      body: { enabled: false },
    });
    check(
      "an admin pauses a provider (200)",
      off.status === 200 && off.json?.data?.enabled === false,
      off.json,
    );
    const on = await call(admin.jar, "PATCH", "/api/integrations/virustotal", {
      body: { enabled: true },
    });
    check(
      "(cleanup) turned it back on",
      on.status === 200 && on.json?.data?.enabled === true,
      on.json,
    );
  }

  section("Automatic data: public feeds and lookups (no network needed)");
  {
    const catalog = await call(analyst.jar, "GET", "/api/integrations");
    for (const provider of ["abusech", "cisa_kev"]) {
      const row = catalog.json?.data?.find((r) => r.provider === provider);
      check(
        `the ${provider} feed is in the catalog, needs no key and is on by default`,
        row?.configured === true && row?.enabled === true,
        row,
      );
    }

    const anonymous = await call(null, "POST", "/api/feeds/import", { body: {} });
    check("importing feeds needs a session (401)", anonymous.status === 401, anonymous.status);
    for (const [name, who] of [
      ["a viewer", viewer],
      ["an analyst", analyst],
    ]) {
      const denied = await call(who.jar, "POST", "/api/feeds/import", { body: {} });
      check(`${name} cannot import feeds (403)`, denied.status === 403, denied.status);
    }
    const badGroup = await call(admin.jar, "POST", "/api/feeds/import", {
      body: { groups: ["not-a-feed"] },
    });
    check("an unknown feed group is refused (422)", badGroup.status === 422, badGroup.json);
    const extra = await call(admin.jar, "POST", "/api/feeds/import", {
      body: { groups: ["abusech"], url: "http://169.254.169.254/" },
    });
    check("a body cannot smuggle in an address (422)", extra.status === 422, extra.json);

    // Pause both groups, so "import now" does its bookkeeping without touching the network.
    for (const provider of ["abusech", "cisa_kev"]) {
      await call(admin.jar, "PATCH", `/api/integrations/${provider}`, { body: { enabled: false } });
    }
    const paused = await call(admin.jar, "POST", "/api/feeds/import", { body: {} });
    check(
      "a paused group is skipped by Import now (every feed reports disabled)",
      paused.status === 200 &&
        paused.json?.data?.length === 4 &&
        paused.json.data.every((r) => r.status === "disabled" && r.fetched === 0),
      paused.json,
    );
    for (const provider of ["abusech", "cisa_kev"]) {
      const back = await call(admin.jar, "PATCH", `/api/integrations/${provider}`, {
        body: { enabled: true },
      });
      check(`(cleanup) ${provider} turned back on`, back.json?.data?.enabled === true, back.json);
    }

    const audit = await call(admin.jar, "GET", "/api/audit-logs?action=feeds.imported&page_size=5");
    check(
      "an import is audited, saying who asked",
      audit.json?.data?.items?.some(
        (e) => e.action === "feeds.imported" && e.metadata?.trigger === "manual" && e.user_id,
      ),
      audit.json?.data?.items?.[0],
    );

    const lookup = await call(analyst.jar, "GET", "/api/intel/ip?value=8.8.4.4");
    check(
      "a demo answer is never recorded as an indicator",
      lookup.status === 200 && lookup.json?.data?.recorded === null,
      lookup.json?.data?.recorded,
    );
    const stored = await call(analyst.jar, "GET", "/api/indicators?q=8.8.4.4");
    check(
      "...and the value did not appear in the indicator list",
      stored.status === 200 && stored.json?.data?.items?.length === 0,
      stored.json?.data?.items?.length,
    );
  }

  section("AI: settings and per-alert analysis (no provider keys in this environment)");
  {
    // smokeAlert (and its `base`) was deleted at the end of the investigations section above; this
    // needs its own alert, alive for the rest of this section.
    const madeAiAlert = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: `Smoke AI alert ${stamp}`, severity: "high" },
    });
    const aiAlertId = madeAiAlert.json?.data?.id;
    check(
      "(setup) an alert exists for the AI checks",
      madeAiAlert.status === 201,
      madeAiAlert.json,
    );

    const viewerSettings = await call(viewer.jar, "GET", "/api/ai/settings");
    check(
      "a viewer cannot read AI settings (403)",
      viewerSettings.status === 403,
      viewerSettings.json,
    );
    const analystSettings = await call(analyst.jar, "GET", "/api/ai/settings");
    check(
      "an analyst reads AI settings: five providers, none configured, nothing active",
      analystSettings.status === 200 &&
        analystSettings.json?.data?.providers?.length === 5 &&
        analystSettings.json.data.providers.every((p) => p.configured === false) &&
        analystSettings.json.data.active_provider === null &&
        analystSettings.json.data.ready === false,
      analystSettings.json,
    );

    const analystPatch = await call(analyst.jar, "PATCH", "/api/ai/settings", {
      body: { active_provider: "groq", active_model: null },
    });
    check(
      "an analyst cannot change the active AI provider (403)",
      analystPatch.status === 403,
      analystPatch.json,
    );
    const badProvider = await call(admin.jar, "PATCH", "/api/ai/settings", {
      body: { active_provider: "not-a-provider", active_model: null },
    });
    check("an unknown provider id is rejected (422)", badProvider.status === 422, badProvider.json);
    const modelWithoutProvider = await call(admin.jar, "PATCH", "/api/ai/settings", {
      body: { active_provider: null, active_model: "some-model" },
    });
    check(
      "a model without a provider is rejected (422)",
      modelWithoutProvider.status === 422,
      modelWithoutProvider.json,
    );
    const unconfigured = await call(admin.jar, "PATCH", "/api/ai/settings", {
      body: { active_provider: "groq", active_model: null },
    });
    check(
      "choosing a provider with no server-side key is refused (409)",
      unconfigured.status === 409,
      unconfigured.json,
    );
    const cleared = await call(admin.jar, "PATCH", "/api/ai/settings", {
      body: { active_provider: null, active_model: null },
    });
    check(
      "an admin can (still) clear the choice explicitly (200)",
      cleared.status === 200 && cleared.json?.data?.active_provider === null,
      cleared.json,
    );

    const viewerAnalyses = await call(viewer.jar, "GET", `/api/alerts/${aiAlertId}/ai`);
    check(
      "anyone who can read the alert reads its (empty) AI analysis history",
      viewerAnalyses.status === 200 &&
        viewerAnalyses.json?.data?.history?.length === 0 &&
        JSON.stringify(viewerAnalyses.json.data.latest) === "{}",
      viewerAnalyses.json,
    );
    const viewerAsks = await call(viewer.jar, "POST", `/api/alerts/${aiAlertId}/ai`, {
      body: { kind: "threat_summary" },
    });
    check(
      "a viewer cannot ask for an AI analysis (403)",
      viewerAsks.status === 403,
      viewerAsks.json,
    );
    const badKind = await call(analyst.jar, "POST", `/api/alerts/${aiAlertId}/ai`, {
      body: { kind: "not_a_kind" },
    });
    check("an unknown analysis kind is rejected (422)", badKind.status === 422, badKind.json);
    const noProvider = await call(analyst.jar, "POST", `/api/alerts/${aiAlertId}/ai`, {
      body: { kind: "threat_summary" },
    });
    check(
      "asking with no AI provider configured is a clear 503, not a crash",
      noProvider.status === 503 && code(noProvider) === "DEPENDENCY_UNAVAILABLE",
      noProvider.json,
    );
    // Live provider calls are NOT exercised here: no provider key exists in this environment, the
    // same caveat the live intel providers and the NVD import carry (see docs/API.md).

    const aiAlertDeleted = await call(admin.jar, "DELETE", `/api/alerts/${aiAlertId}`);
    check(
      "(cleanup) the AI checks' alert is deleted",
      aiAlertDeleted.status === 200,
      aiAlertDeleted.json,
    );
  }

  section("Response orchestration and checklists (Phase 9)");
  {
    // --- the response-action catalog ---
    const viewerCreatesAction = await call(viewer.jar, "POST", "/api/response-actions", {
      body: { title: "Smoke isolate the host" },
    });
    check(
      "a viewer cannot add a catalog action (403)",
      viewerCreatesAction.status === 403,
      viewerCreatesAction.json,
    );
    const madeAction = await call(analyst.jar, "POST", "/api/response-actions", {
      body: {
        title: `Smoke isolate the host ${stamp}`,
        description: "Cut network access.",
        category: "containment",
      },
    });
    const action = madeAction.json?.data;
    check(
      "an analyst adds a catalog action (201): local, tidy fields",
      madeAction.status === 201 && action?.origin === "local" && action.category === "containment",
      madeAction.json,
    );
    const catalogList = await call(viewer.jar, "GET", "/api/response-actions");
    check(
      "anyone with alerts:read reads the catalog and finds it",
      catalogList.status === 200 && catalogList.json?.data?.some((a) => a.id === action?.id),
      catalogList.status,
    );
    const renamed = await call(analyst.jar, "PATCH", `/api/response-actions/${action?.id}`, {
      body: { title: `Smoke isolate the endpoint ${stamp}` },
    });
    check(
      "an analyst edits a catalog action (200)",
      renamed.status === 200 && renamed.json?.data?.title === `Smoke isolate the endpoint ${stamp}`,
      renamed.json,
    );

    // --- attached to an alert ---
    const madeOrchAlert = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: `Smoke orchestration alert ${stamp}`, severity: "high" },
    });
    const orchAlertId = madeOrchAlert.json?.data?.id;
    const viewerAttaches = await call(
      viewer.jar,
      "POST",
      `/api/alerts/${orchAlertId}/response-actions`,
      {
        body: { action_id: action?.id },
      },
    );
    check(
      "a viewer cannot recommend a response action (403)",
      viewerAttaches.status === 403,
      viewerAttaches.json,
    );
    const attached = await call(
      analyst.jar,
      "POST",
      `/api/alerts/${orchAlertId}/response-actions`,
      {
        body: { action_id: action?.id },
      },
    );
    const logEntries = attached.json?.data;
    const logId = logEntries?.at(-1)?.id;
    check(
      "an analyst recommends it (201): recommended, source analyst",
      attached.status === 201 &&
        logEntries?.at(-1)?.status === "recommended" &&
        logEntries.at(-1).source === "analyst",
      attached.json,
    );
    const badTransition = await call(
      analyst.jar,
      "PATCH",
      `/api/alerts/${orchAlertId}/response-actions/${logId}`,
      {
        body: { status: "completed" },
      },
    );
    check(
      "recommended -> completed directly is allowed by the workflow (200)",
      badTransition.status === 200,
      badTransition.json,
    );
    const backwards = await call(
      analyst.jar,
      "PATCH",
      `/api/alerts/${orchAlertId}/response-actions/${logId}`,
      {
        body: { status: "acknowledged" },
      },
    );
    check(
      "a completed action cannot move backwards to acknowledged (409)",
      backwards.status === 409,
      backwards.json,
    );
    const cannotDeleteReferenced = await call(
      analyst.jar,
      "DELETE",
      `/api/response-actions/${action?.id}`,
    );
    check(
      "a catalog action with a logged history cannot be deleted (409)",
      cannotDeleteReferenced.status === 409,
      cannotDeleteReferenced.json,
    );

    // --- investigation checklist ---
    const madeOrchInv = await call(analyst.jar, "POST", "/api/investigations", {
      body: { title: `Smoke orchestration case ${stamp}` },
    });
    const orchInvId = madeOrchInv.json?.data?.id;
    const viewerAddsItem = await call(
      viewer.jar,
      "POST",
      `/api/investigations/${orchInvId}/checklist`,
      {
        body: { text: "Smoke viewer item" },
      },
    );
    check(
      "a viewer cannot add a checklist item (403)",
      viewerAddsItem.status === 403,
      viewerAddsItem.json,
    );
    const addedItem = await call(
      analyst.jar,
      "POST",
      `/api/investigations/${orchInvId}/checklist`,
      {
        body: { text: "Pull DNS logs for the affected host" },
      },
    );
    const items = addedItem.json?.data;
    const itemId = items?.at(-1)?.id;
    check(
      "an analyst adds a checklist item by hand (201), source analyst",
      addedItem.status === 201 && items?.at(-1)?.source === "analyst",
      addedItem.json,
    );
    const toggled = await call(
      analyst.jar,
      "PATCH",
      `/api/investigations/${orchInvId}/checklist/${itemId}`,
      {
        body: { done: true },
      },
    );
    check(
      "checking it off records done (200)",
      toggled.status === 200 && toggled.json?.data?.find((i) => i.id === itemId)?.done === true,
      toggled.json,
    );
    const removedItem = await call(
      analyst.jar,
      "DELETE",
      `/api/investigations/${orchInvId}/checklist/${itemId}`,
    );
    check(
      "removing it leaves the list empty (200)",
      removedItem.status === 200 && removedItem.json?.data?.length === 0,
      removedItem.json,
    );

    const badInvKind = await call(analyst.jar, "POST", `/api/investigations/${orchInvId}/ai`, {
      body: { kind: "threat_summary" },
    });
    check(
      "an alert-only AI kind is rejected for an investigation (422)",
      badInvKind.status === 422,
      badInvKind.json,
    );
    const invNoProvider = await call(analyst.jar, "POST", `/api/investigations/${orchInvId}/ai`, {
      body: { kind: "investigation_checklist" },
    });
    check(
      "asking for a checklist with no AI provider configured is a clear 503",
      invNoProvider.status === 503 && code(invNoProvider) === "DEPENDENCY_UNAVAILABLE",
      invNoProvider.json,
    );

    // --- indicator verdict recommendation ---
    const madeOrchIndicator = await call(analyst.jar, "POST", "/api/indicators", {
      body: { type: "domain", value: `smoke-orch-${stamp}.example` },
    });
    const orchIndicatorId = madeOrchIndicator.json?.data?.id;
    const badIndKind = await call(analyst.jar, "POST", `/api/indicators/${orchIndicatorId}/ai`, {
      body: { kind: "false_positive_score" },
    });
    check(
      "an alert-only AI kind is rejected for an indicator (422)",
      badIndKind.status === 422,
      badIndKind.json,
    );
    const indNoProvider = await call(analyst.jar, "POST", `/api/indicators/${orchIndicatorId}/ai`, {
      body: { kind: "verdict_recommendation" },
    });
    check(
      "asking for a verdict recommendation with no AI provider configured is a clear 503",
      indNoProvider.status === 503 && code(indNoProvider) === "DEPENDENCY_UNAVAILABLE",
      indNoProvider.json,
    );

    // --- cleanup ---
    await call(admin.jar, "DELETE", `/api/alerts/${orchAlertId}`);
    await call(admin.jar, "DELETE", `/api/investigations/${orchInvId}`);
    await call(admin.jar, "DELETE", `/api/indicators/${orchIndicatorId}`);
    const finalDelete = await call(admin.jar, "DELETE", `/api/response-actions/${action?.id}`);
    check(
      "(cleanup) the catalog action is deleted once its alert is gone",
      finalDelete.status === 200,
      finalDelete.json,
    );
  }

  section("Detection rules and alert deduplication (Phase 10)");
  {
    // A rule id derived from the run's own stamp: unique per run, always inside 100000-999999.
    const ruleId = 100000 + (stamp % 899999);
    const marker = `drmarker${stamp}`;

    const viewerCreatesRule = await call(viewer.jar, "POST", "/api/detection-rules", {
      body: {
        id: ruleId,
        name: "Smoke viewer rule",
        conditions: [{ field: "title", op: "contains", value: marker }],
      },
    });
    check(
      "a viewer cannot create a detection rule (403)",
      viewerCreatesRule.status === 403,
      viewerCreatesRule.json,
    );
    const analystCreatesRule = await call(analyst.jar, "POST", "/api/detection-rules", {
      body: {
        id: ruleId,
        name: "Smoke analyst rule",
        conditions: [{ field: "title", op: "contains", value: marker }],
      },
    });
    check(
      "an analyst cannot create a detection rule either: rules:manage is admin only (403)",
      analystCreatesRule.status === 403,
      analystCreatesRule.json,
    );

    const badRange = await call(admin.jar, "POST", "/api/detection-rules", {
      body: {
        id: 1,
        name: "Smoke bad id",
        conditions: [{ field: "title", op: "contains", value: marker }],
      },
    });
    check(
      "a rule id outside 100000-999999 is rejected (422)",
      badRange.status === 422,
      badRange.json,
    );
    const badConditions = await call(admin.jar, "POST", "/api/detection-rules", {
      body: { id: ruleId, name: "Smoke empty conditions", conditions: [] },
    });
    check(
      "an empty conditions array is rejected (422)",
      badConditions.status === 422,
      badConditions.json,
    );

    const madeRule = await call(admin.jar, "POST", "/api/detection-rules", {
      body: {
        id: ruleId,
        name: `Smoke rule ${stamp}`,
        conditions: [{ field: "title", op: "contains", value: marker }],
        severity: "critical",
      },
    });
    const rule = madeRule.json?.data;
    check(
      "an admin creates a rule (201): local, the id given, enabled by default",
      madeRule.status === 201 &&
        rule?.id === ruleId &&
        rule.origin === "local" &&
        rule.enabled === true,
      madeRule.json,
    );
    const ruleList = await call(viewer.jar, "GET", "/api/detection-rules");
    check(
      "anyone with alerts:read reads the rule catalog and finds it",
      ruleList.status === 200 && ruleList.json?.data?.some((r) => r.id === ruleId),
      ruleList.status,
    );

    const matchingAlert = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: `Smoke ${marker} triggers a rule`, severity: "low" },
    });
    const matchedAlertId = matchingAlert.json?.data?.id;
    check(
      "a new alert matching an enabled rule has its severity raised and traces the rule (201)",
      matchingAlert.status === 201 &&
        matchingAlert.json.data.severity === "critical" &&
        matchingAlert.json.data.matched_rule_id === ruleId,
      matchingAlert.json,
    );
    const matchedDetail = await call(analyst.jar, "GET", `/api/alerts/${matchedAlertId}`);
    check(
      "the alert page shows which rule matched, by name",
      matchedDetail.status === 200 && matchedDetail.json?.data?.matched_rule?.id === ruleId,
      matchedDetail.json?.data?.matched_rule,
    );

    const disabled = await call(admin.jar, "PATCH", `/api/detection-rules/${ruleId}`, {
      body: { enabled: false },
    });
    check(
      "an admin disables the rule (200)",
      disabled.status === 200 && disabled.json?.data?.enabled === false,
      disabled.json,
    );
    const afterDisable = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: `Smoke ${marker} but the rule is off`, severity: "low" },
    });
    check(
      "a disabled rule no longer matches new alerts",
      afterDisable.status === 201 &&
        afterDisable.json.data.severity === "low" &&
        afterDisable.json.data.matched_rule_id === null,
      afterDisable.json,
    );

    const analystDeletesRule = await call(analyst.jar, "DELETE", `/api/detection-rules/${ruleId}`);
    check(
      "an analyst cannot delete a rule (403)",
      analystDeletesRule.status === 403,
      analystDeletesRule.json,
    );

    // --- deduplication ---
    const dupTitle = `Smoke duplicate source ${stamp}`;
    const firstOfPair = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: dupTitle, severity: "medium" },
    });
    const firstId = firstOfPair.json?.data?.id;
    check(
      "a first occurrence is its own primary (no duplicate_of)",
      firstOfPair.status === 201 && firstOfPair.json.data.duplicate_of === null,
      firstOfPair.json,
    );
    const secondOfPair = await call(analyst.jar, "POST", "/api/alerts", {
      body: { title: dupTitle, severity: "medium" },
    });
    const secondId = secondOfPair.json?.data?.id;
    check(
      "a second, identical occurrence links to the first as a duplicate",
      secondOfPair.status === 201 && secondOfPair.json.data.duplicate_of === firstId,
      secondOfPair.json,
    );
    const firstAfterDup = await call(analyst.jar, "GET", `/api/alerts/${firstId}`);
    check(
      "the primary's duplicate_count reaches 1 and it lists the duplicate",
      firstAfterDup.status === 200 &&
        firstAfterDup.json?.data?.duplicate_count === 1 &&
        firstAfterDup.json.data.duplicates?.[0]?.id === secondId,
      firstAfterDup.json?.data,
    );
    const hiddenByDefault = await call(
      analyst.jar,
      "GET",
      `/api/alerts?q=${encodeURIComponent(dupTitle)}`,
    );
    check(
      "the default list hides the duplicate, showing only the primary",
      hiddenByDefault.status === 200 && hiddenByDefault.json?.data?.items?.length === 1,
      hiddenByDefault.json?.data?.items,
    );
    const shownWithFilter = await call(
      analyst.jar,
      "GET",
      `/api/alerts?q=${encodeURIComponent(dupTitle)}&duplicates=show`,
    );
    check(
      "duplicates=show reveals both alerts",
      shownWithFilter.status === 200 && shownWithFilter.json?.data?.items?.length === 2,
      shownWithFilter.json?.data?.items,
    );

    // --- cleanup ---
    for (const id of [matchedAlertId, afterDisable.json?.data?.id, firstId, secondId]) {
      if (id) await call(admin.jar, "DELETE", `/api/alerts/${id}`);
    }
    const finalRuleDelete = await call(admin.jar, "DELETE", `/api/detection-rules/${ruleId}`);
    check(
      "(cleanup) an admin deletes the rule",
      finalRuleDelete.status === 200,
      finalRuleDelete.json,
    );
  }

  section("Wazuh rules (detection-as-code)");
  {
    const body = {
      name: `Smoke wazuh rule ${stamp}`,
      description: "Created by the smoke test.",
      level: 9,
      parent_kind: "group",
      parent_value: "windows",
      conditions: [{ field: "win.eventdata.commandLine", op: "contains", value: `smk${stamp}` }],
      mitre_ids: ["T1562.001"],
    };

    for (const [label, who] of [
      ["a viewer", viewer],
      ["an analyst", analyst],
    ]) {
      const listed = await call(who.jar, "GET", "/api/wazuh-rules");
      check(`${label} cannot list Wazuh rules (403)`, listed.status === 403, listed.json);
      const created = await call(who.jar, "POST", "/api/wazuh-rules", { body });
      check(`${label} cannot create a Wazuh rule (403)`, created.status === 403, created.json);
    }

    const unsafe = await call(admin.jar, "POST", "/api/wazuh-rules", {
      body: { ...body, conditions: [{ field: "win.a.b", op: "regex", value: "(a+)+" }] },
    });
    check("an unsafe regex is refused (422)", unsafe.status === 422, unsafe.json);
    const badField = await call(admin.jar, "POST", "/api/wazuh-rules", {
      body: { ...body, conditions: [{ field: "full_log", op: "contains", value: "x" }] },
    });
    check("a field outside the known prefixes is refused (422)", badField.status === 422);
    const lowId = await call(admin.jar, "POST", "/api/wazuh-rules", {
      body: { ...body, id: 100001 },
    });
    check("an id below the reserved floor is refused (422)", lowId.status === 422);
    const forged = await call(admin.jar, "POST", "/api/wazuh-rules", {
      body: { ...body, origin: "external", status: "pushed" },
    });
    check("origin and status are not the client's to set (422)", forged.status === 422);
    const injected = await call(admin.jar, "POST", "/api/wazuh-rules", {
      body: { ...body, parent_value: "windows</if_group><active-response>" },
    });
    check("an XML fragment in the parent group is refused (422)", injected.status === 422);

    const made = await call(admin.jar, "POST", "/api/wazuh-rules", { body });
    const rule = made.json?.data;
    check(
      "an admin creates a draft; the server picks the id and renders the XML",
      made.status === 201 &&
        rule?.status === "draft" &&
        rule?.source === "manual" &&
        rule?.id >= 100100 &&
        rule?.xml?.includes(`<rule id="${rule?.id}" level="9">`) &&
        rule?.xml?.includes("<if_group>windows</if_group>") &&
        !rule?.xml?.includes("active-response"),
      made.json,
    );
    const ruleId = rule?.id;

    if (ruleId) {
      const listed = await call(admin.jar, "GET", "/api/wazuh-rules");
      check(
        "the list contains the new rule",
        listed.status === 200 && listed.json?.data?.some((item) => item.id === ruleId),
      );
      const edited = await call(admin.jar, "PATCH", `/api/wazuh-rules/${ruleId}`, {
        body: { level: 11 },
      });
      check(
        "an edit changes the level and the XML",
        edited.status === 200 &&
          edited.json?.data?.level === 11 &&
          edited.json?.data?.xml?.includes('level="11"'),
        edited.json,
      );
      const idChange = await call(admin.jar, "PATCH", `/api/wazuh-rules/${ruleId}`, {
        body: { id: 100999 },
      });
      check("the id cannot be changed (422)", idChange.status === 422);

      const pushNoGithub = await call(admin.jar, "POST", `/api/wazuh-rules/${ruleId}/push`);
      check(
        "sending to GitHub is refused (503) while the server has no GitHub token",
        pushNoGithub.status === 503,
        pushNoGithub.json,
      );
      const stillDraft = await call(admin.jar, "GET", `/api/wazuh-rules/${ruleId}`);
      check("a failed push leaves the rule a draft", stillDraft.json?.data?.status === "draft");

      const rejected = await call(admin.jar, "POST", `/api/wazuh-rules/${ruleId}/reject`, {
        body: { reason: "smoke" },
      });
      check(
        "rejecting a draft records the reason",
        rejected.status === 200 &&
          rejected.json?.data?.status === "rejected" &&
          rejected.json?.data?.reject_reason === "smoke",
        rejected.json,
      );
      const rejectAgain = await call(admin.jar, "POST", `/api/wazuh-rules/${ruleId}/reject`, {
        body: {},
      });
      check("a rejected rule cannot be rejected again (409)", rejectAgain.status === 409);
      const pushRejected = await call(admin.jar, "POST", `/api/wazuh-rules/${ruleId}/push`);
      check("a rejected rule cannot be pushed (409)", pushRejected.status === 409);
      const restored = await call(admin.jar, "PATCH", `/api/wazuh-rules/${ruleId}`, {
        body: { level: 8 },
      });
      check(
        "editing a rejected rule brings it back to a draft",
        restored.status === 200 && restored.json?.data?.status === "draft",
        restored.json,
      );

      const removed = await call(admin.jar, "DELETE", `/api/wazuh-rules/${ruleId}`);
      check("an admin deletes a draft", removed.status === 200, removed.json);
      const gone = await call(admin.jar, "GET", `/api/wazuh-rules/${ruleId}`);
      check("a deleted rule is gone (404)", gone.status === 404);
    }

    const shortPrompt = await call(admin.jar, "POST", "/api/wazuh-rules/generate", {
      body: { prompt: "x" },
    });
    check("a too-short AI request is refused (422)", shortPrompt.status === 422);
    const viewerGenerates = await call(viewer.jar, "POST", "/api/wazuh-rules/generate", {
      body: { prompt: "Detect PowerShell disabling Defender." },
    });
    check("a viewer cannot ask the AI for a rule (403)", viewerGenerates.status === 403);
    const generated = await call(admin.jar, "POST", "/api/wazuh-rules/generate", {
      body: { prompt: `Detect the marker smk${stamp} in a PowerShell command line.` },
    });
    check(
      "generating a rule is either a draft (a provider is ready) or a clear 503 (none is)",
      generated.status === 503 ||
        (generated.status === 201 &&
          generated.json?.data?.source === "ai" &&
          generated.json?.data?.status === "draft"),
      generated.json,
    );
    if (generated.status === 201) {
      await call(admin.jar, "DELETE", `/api/wazuh-rules/${generated.json.data.id}`);
    }
  }

  section("Profile");
  {
    const before = await call(viewer.jar, "GET", "/api/auth/me");
    const originalName = before.json?.data?.profile?.display_name ?? null;
    const noFields = await call(viewer.jar, "PATCH", "/api/auth/me", { body: {} });
    check("an empty profile update is 422", noFields.status === 422, noFields.json);
    const badUrl = await call(viewer.jar, "PATCH", "/api/auth/me", {
      body: { avatar_url: "not a url" },
    });
    check("an invalid avatar URL is 422", badUrl.status === 422, badUrl.json);
    const renamed = await call(viewer.jar, "PATCH", "/api/auth/me", {
      body: { display_name: `smoke-${stamp}` },
    });
    check(
      "a signed-in user renames themselves",
      renamed.status === 200 && renamed.json?.data?.profile?.display_name === `smoke-${stamp}`,
      renamed.json,
    );
    const cleared = await call(viewer.jar, "PATCH", "/api/auth/me", { body: { display_name: "" } });
    check(
      "an empty string clears the name (falls back to null)",
      cleared.status === 200 && cleared.json?.data?.profile?.display_name === null,
      cleared.json,
    );
    const restored = await call(viewer.jar, "PATCH", "/api/auth/me", {
      body: { display_name: originalName },
    });
    check("(cleanup) display name restored", restored.status === 200, restored.json);
  }

  section("User management (throwaway account, demo accounts never touched)");
  {
    const email = `smoke-users-${stamp}@arcradar.test`;
    const signup = await call(null, "POST", "/api/auth/signup", {
      body: { email, password: "Smoke-Users-Pass-1" },
    });
    const login = await loginAs(email, "Smoke-Users-Pass-1");
    const targetId = login.response.json?.data?.user?.id;
    check("(setup) throwaway account created and signed in", signup.status === 201 && !!targetId);

    try {
      const deniedList = await call(analyst.jar, "GET", "/api/users");
      check("an analyst cannot list accounts (403)", deniedList.status === 403, deniedList.json);
      const list = await call(admin.jar, "GET", "/api/users");
      check(
        "an admin lists every account, including the new one, with no password hash anywhere",
        list.status === 200 &&
          list.json.data.some((u) => u.id === targetId) &&
          !JSON.stringify(list.json.data).toLowerCase().includes("password"),
        list.status,
      );

      const selfChange = await call(
        admin.jar,
        "PATCH",
        `/api/users/${adminMe.json?.data?.user?.id}`,
        {
          body: { is_active: false },
        },
      );
      check(
        "an admin cannot change their own account here (409)",
        selfChange.status === 409,
        selfChange.json,
      );

      const promote = await call(admin.jar, "PATCH", `/api/users/${targetId}`, {
        body: { role_name: "analyst" },
      });
      check("an admin promotes the account (200)", promote.status === 200, promote.json);
      const deactivate = await call(admin.jar, "PATCH", `/api/users/${targetId}`, {
        body: { is_active: false },
      });
      check("an admin deactivates it (200)", deactivate.status === 200, deactivate.json);
      const lockedOut = await call(login.jar, "GET", "/api/auth/me");
      check("its live session is refused at once (403)", lockedOut.status === 403, lockedOut.json);

      const userLogs = await call(
        admin.jar,
        "GET",
        `/api/audit-logs?entity_type=profile&entity_id=${targetId}`,
      );
      const userActions = new Set((userLogs.json?.data?.items ?? []).map((e) => e.action));
      check(
        "role and status changes are audited",
        userActions.has("user.role_changed") && userActions.has("user.deactivated"),
        [...userActions],
      );
    } finally {
      const removed = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${targetId}`, {
        method: "DELETE",
        headers: { apikey: SERVICE_KEY, authorization: `Bearer ${SERVICE_KEY}` },
      });
      check("(cleanup) throwaway account deleted", removed.ok || !targetId, removed.status);
    }
  }

  section("Logout");
  const logout = await call(viewer.jar, "POST", "/api/auth/logout");
  check("logout is 200", logout.status === 200, logout.json);
  const afterLogout = await call(viewer.jar, "GET", "/api/auth/me");
  check("session is gone after logout (401)", afterLogout.status === 401, afterLogout.json);
  const loggedOutAgain = await call(new Jar(), "POST", "/api/auth/logout");
  check(
    "logout without a session still succeeds",
    loggedOutAgain.status === 200,
    loggedOutAgain.json,
  );

  section("Signup, disabled accounts, password recovery");
  const email = `smoke-${Date.now()}@arcradar.test`;
  const firstPassword = "Smoke-Test-Pass-1";
  const secondPassword = "Smoke-Test-Pass-2";
  let newUserId = null;
  try {
    const signup = await call(null, "POST", "/api/auth/signup", {
      body: { email, password: firstPassword, display_name: "Smoke Tester" },
    });
    check(
      "signup is 201",
      signup.status === 201 && signup.json?.data?.registered === true,
      signup.json,
    );
    const again = await call(null, "POST", "/api/auth/signup", {
      body: { email, password: firstPassword },
    });
    check(
      "signing up an existing email gives the identical response",
      again.status === 201 && again.text === signup.text,
      again.json,
    );
    const withRole = await call(null, "POST", "/api/auth/signup", {
      body: { email: `x-${email}`, password: firstPassword, role_name: "admin" },
    });
    check("signup rejects a role field (422)", withRole.status === 422, withRole.json);
    const weak = await call(null, "POST", "/api/auth/signup", {
      body: { email: `y-${email}`, password: "weakpass" },
    });
    check("signup enforces the password policy (422)", weak.status === 422, weak.json);

    const fresh = await loginAs(email, firstPassword);
    check("new user can sign in", fresh.response.status === 200, fresh.response.json);
    check(
      "new users are always viewers",
      fresh.response.json?.data?.profile?.role === "viewer" &&
        fresh.response.json.data.profile.display_name === "Smoke Tester",
      fresh.response.json?.data?.profile,
    );
    newUserId = fresh.response.json?.data?.user?.id ?? null;

    // Disabled account: the API must lock the user out immediately, even with a live session.
    if (newUserId) {
      const disable = await adminRest("PATCH", `/rest/v1/profiles?id=eq.${newUserId}`, {
        is_active: false,
      });
      check(
        "(setup) deactivated the profile with the service role",
        disable.status === 204,
        disable,
      );
      const disabledMe = await call(fresh.jar, "GET", "/api/auth/me");
      check(
        "existing session of a disabled user is refused (403)",
        disabledMe.status === 403 && code(disabledMe) === "ACCOUNT_DISABLED",
        disabledMe.json,
      );
      const disabledLogin = await loginAs(email, firstPassword);
      check(
        "disabled user cannot sign in (403) and gets no cookies",
        disabledLogin.response.status === 403 &&
          code(disabledLogin.response) === "ACCOUNT_DISABLED" &&
          disabledLogin.jar.cookies.size === 0,
        disabledLogin.response.json,
      );
      await adminRest("PATCH", `/rest/v1/profiles?id=eq.${newUserId}`, { is_active: true });
    }

    // Recovery email -> callback -> update password.
    const recoveryJar = new Jar();
    const knownIds = new Set(
      ((await (await fetch(`${MAILPIT}/api/v1/messages`)).json()).messages ?? []).map((m) => m.ID),
    );
    const forgot = await call(recoveryJar, "POST", "/api/auth/forgot-password", {
      body: { email },
    });
    check(
      "forgot-password is 200",
      forgot.status === 200 && forgot.json?.data?.sent === true,
      forgot.json,
    );
    const unknownForgot = await call(null, "POST", "/api/auth/forgot-password", {
      body: { email: `nobody-${email}` },
    });
    check(
      "forgot-password for an unknown email is identical (no enumeration)",
      unknownForgot.status === 200 && unknownForgot.text === forgot.text,
      unknownForgot.json,
    );

    const mail = await latestMailTo(email, knownIds);
    check("recovery email arrived in Mailpit", !!mail);
    const link =
      mail &&
      /https?:\/\/[^\s"'<>]+\/auth\/v1\/verify\?[^\s"'<>]+/
        .exec(mail.Text + mail.HTML)?.[0]
        .replaceAll("&amp;", "&");
    check("recovery email contains a verify link", !!link, mail?.Text?.slice(0, 200));

    if (link) {
      const verify = await fetch(link, { redirect: "manual" });
      const landing = verify.headers.get("location") ?? "";
      check(
        "Supabase redirects to the app callback with a code",
        landing.startsWith(`http://localhost:3000/auth/callback`) && landing.includes("code="),
        landing,
      );

      if (landing.includes("code=")) {
        const callbackPath = landing.replace(/^https?:\/\/[^/]+/, "");
        const callback = await call(recoveryJar, "GET", callbackPath);
        check(
          "callback exchanges the code and redirects to /reset-password",
          callback.status === 307 &&
            (callback.headers.get("location") ?? "").endsWith("/reset-password"),
          { status: callback.status, location: callback.headers.get("location") },
        );
        const recoveryMe = await call(recoveryJar, "GET", "/api/auth/me");
        check("recovery session is signed in", recoveryMe.status === 200, recoveryMe.json);
        const replay = await call(new Jar(), "GET", callbackPath);
        check(
          "the recovery code cannot be replayed",
          (replay.headers.get("location") ?? "").includes("/login?error="),
          replay.headers.get("location"),
        );

        const weakUpdate = await call(recoveryJar, "POST", "/api/auth/update-password", {
          body: { password: "short" },
        });
        check(
          "update-password enforces the policy (422)",
          weakUpdate.status === 422,
          weakUpdate.json,
        );
        const update = await call(recoveryJar, "POST", "/api/auth/update-password", {
          body: { password: secondPassword },
        });
        check("update-password is 200", update.status === 200, update.json);
        const oldLogin = await loginAs(email, firstPassword);
        check(
          "old password no longer works",
          oldLogin.response.status === 401,
          oldLogin.response.json,
        );
        const newLogin = await loginAs(email, secondPassword);
        check("new password works", newLogin.response.status === 200, newLogin.response.json);
      }
    }
  } finally {
    if (newUserId) {
      const removed = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${newUserId}`, {
        method: "DELETE",
        headers: { apikey: SERVICE_KEY, authorization: `Bearer ${SERVICE_KEY}` },
      });
      check("(cleanup) throwaway user deleted", removed.ok, removed.status);
    }
  }

  section("Audit trail after the recovery flow");
  const finalLogs = await call(admin.jar, "GET", "/api/audit-logs?page_size=100");
  const actions = new Set((finalLogs.json?.data?.items ?? []).map((e) => e.action));
  for (const action of [
    "auth.signup",
    "auth.password_reset_requested",
    "auth.email_link_session",
    "auth.password_changed",
  ]) {
    check(`audit contains ${action}`, actions.has(action), [...actions]);
  }
  const trail = JSON.stringify(finalLogs.json?.data?.items ?? []);
  check(
    "no passwords or tokens in the audit trail",
    !trail.includes(firstPassword) &&
      !trail.includes(secondPassword) &&
      !/access_token|refresh_token/.test(trail),
  );

  console.log(`\n${passes} passed, ${failures} failed`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error("Smoke test crashed:", error);
  process.exit(1);
});
