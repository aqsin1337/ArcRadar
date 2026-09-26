// End-to-end smoke test of the auth + RBAC + audit + indicators API against a RUNNING app and the local
// Supabase stack (npm run db:start, then npm run dev or npm start). Local only: it signs in with the
// demo users, creates a throwaway user through the public signup endpoint, reads the recovery email
// from Mailpit, and deletes that user again with the service-role key from .env.local.
//
//   npm run api:smoke                        # against http://localhost:3000
//   SMOKE_BASE_URL=http://localhost:8080 npm run api:smoke   # through nginx
//
// Supabase limits sign-ins/sign-ups to 30 per 5 minutes per IP, so avoid back-to-back runs.
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
    "detail returns the indicator with tags, links and relationships",
    detail.status === 200 &&
      detail.json.data.id === indicator?.id &&
      Array.isArray(detail.json.data.relationships) &&
      Array.isArray(detail.json.data.threat_actors),
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
    "a seeded indicator shows its linked actors and relationships",
    seededDetail.status === 200 &&
      seededDetail.json.data.threat_actors.length > 0 &&
      seededDetail.json.data.origin === "demo",
    seededDetail.json?.data && {
      actors: seededDetail.json.data.threat_actors,
      rel: seededDetail.json.data.relationships,
    },
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
