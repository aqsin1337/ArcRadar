import { notFound } from "next/navigation";
import { beforeEach, describe, expect, it, vi } from "vitest";
import samples from "../scripts/fixtures/wazuh-sample-alerts.json";
import { ApiError, apiErrors } from "@/lib/api/errors";
import { ok } from "@/lib/api/response";
import { formatRelative } from "@/lib/format";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import { buildSourceCards, statusOf } from "@/lib/telemetry/health";
import {
  assetListQuerySchema,
  eventListQuerySchema,
  parseEventListParams,
} from "@/lib/telemetry/schema";
import type { SourceHealth } from "@/lib/telemetry/types";
import { wazuhSource } from "@/lib/telemetry/wazuh";
import { apiRequest } from "./helpers/supabase";

const verify = vi.hoisted(() => vi.fn());
const store = vi.hoisted(() => vi.fn());
const audit = vi.hoisted(() => vi.fn());
const cookieClient = vi.hoisted(() =>
  vi.fn(() => {
    throw new Error("the cookie-based client must never be used by an ingest route");
  }),
);
vi.mock("@/lib/api-keys/service", () => ({ verifyApiKey: verify }));
vi.mock("@/lib/telemetry/repository", () => ({
  ingestRecords: store,
  findSourceHealth: vi.fn(),
  findAssets: vi.fn(),
  findEvents: vi.fn(),
}));
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/supabase/server", () => ({ createClient: cookieClient }));
vi.mock("@/lib/supabase/session", () => ({ updateSession: vi.fn() }));

const { ingestRoute } = await import("@/lib/api/ingest-route");
const { POST } = await import("@/app/api/ingest/wazuh/route");
const { ingestBatch } = await import("@/lib/telemetry/service");
const { config: proxyConfig } = await import("@/proxy");

const [bruteForce, , , , , logon] = samples as Record<string, unknown>[];
const KEY = `arc_${"K".repeat(43)}`;
const PRINCIPAL: ApiKeyPrincipal = {
  keyId: "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d",
  keyName: "Wazuh lab",
  keyPrefix: "arc_KKKK",
  ownerId: "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69",
  scopes: ["ingest:wazuh"],
};
const SUMMARY = {
  events_created: 2,
  alerts_created: 1,
  duplicates: 0,
  assets_created: 1,
  indicators_created: 1,
};

const post = (body: unknown, headers: Record<string, string> = {}) =>
  POST(
    apiRequest("/api/ingest/wazuh", {
      body,
      headers: { authorization: `Bearer ${KEY}`, ...headers },
    }),
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
  verify.mockResolvedValue(PRINCIPAL);
  store.mockResolvedValue(SUMMARY);
  audit.mockResolvedValue(true);
});

describe("ingestRoute", () => {
  it("asks for a key before anything else, and answers in the usual envelope", async () => {
    verify.mockRejectedValue(
      new ApiError(401, "UNAUTHENTICATED", "The API key is not valid.", undefined, {
        "WWW-Authenticate": 'Bearer realm="ArcRadar"',
      }),
    );
    const handler = vi.fn(async () => ok({ reached: true }));
    const response = await ingestRoute(
      { scope: "ingest:wazuh" },
      handler,
    )(apiRequest("/api/x", { method: "POST" }));

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe('Bearer realm="ArcRadar"');
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(await response.json()).toEqual({
      success: false,
      data: null,
      error: { code: "UNAUTHENTICATED", message: "The API key is not valid." },
    });
    expect(verify).toHaveBeenCalledWith(null, "ingest:wazuh"); // no header, no token
    expect(handler).not.toHaveBeenCalled();
  });

  it("hands the bearer token and the scope to the check, then the principal to the handler", async () => {
    const handler = vi.fn(async ({ principal }: { principal: ApiKeyPrincipal }) =>
      ok({ owner: principal.ownerId }),
    );
    const response = await ingestRoute(
      { scope: "ingest:wazuh" },
      handler,
    )(apiRequest("/api/x", { method: "POST", headers: { authorization: `bearer ${KEY}` } }));
    expect(verify).toHaveBeenCalledWith(KEY, "ingest:wazuh");
    expect((await response.json()).data).toEqual({ owner: PRINCIPAL.ownerId });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("does not use cookies, so a browser session cannot stand in for a key and no same-origin check applies", async () => {
    const handler = vi.fn(async () => ok(null));
    // A cross-origin browser request with cookies is just a request without a key: it fails the key check.
    verify.mockRejectedValue(apiErrors.unauthenticated("The API key is not valid."));
    const response = await ingestRoute(
      { scope: "ingest:wazuh" },
      handler,
    )(
      apiRequest("/api/x", {
        method: "POST",
        headers: { origin: "https://evil.example", cookie: "sb-token=abc" },
      }),
    );
    expect(response.status).toBe(401);
    expect(cookieClient).not.toHaveBeenCalled();

    // A machine sending an Origin of its own is not refused for it either (the check is for browsers).
    verify.mockResolvedValue(PRINCIPAL);
    const machine = await ingestRoute(
      { scope: "ingest:wazuh" },
      handler,
    )(
      apiRequest("/api/x", {
        method: "POST",
        headers: { origin: "https://manager.example", authorization: `Bearer ${KEY}` },
      }),
    );
    expect(machine.status).toBe(200);
    expect(cookieClient).not.toHaveBeenCalled();
  });

  it("maps a thrown error like the other wrappers: known errors as they are, anything else as a generic 500", async () => {
    const throwing = (error: unknown) =>
      ingestRoute({ scope: "ingest:wazuh" }, async () => {
        throw error;
      })(apiRequest("/api/x", { method: "POST", headers: { authorization: `Bearer ${KEY}` } }));

    const forbidden = await throwing(apiErrors.forbidden("nope"));
    expect(forbidden.status).toBe(403);
    const broken = await throwing(new Error("connection string leaked: postgres://secret"));
    expect(broken.status).toBe(500);
    expect(JSON.stringify(await broken.json())).not.toContain("secret");
  });

  it("lets the framework's own control-flow errors through instead of turning them into a 500", async () => {
    const route = ingestRoute({ scope: "ingest:wazuh" }, async () => notFound());
    await expect(
      route(apiRequest("/api/x", { method: "POST", headers: { authorization: `Bearer ${KEY}` } })),
    ).rejects.toMatchObject({ digest: expect.stringContaining("NEXT_HTTP_ERROR_FALLBACK") });
  });

  it("a key that lacks the scope is refused before the handler runs", async () => {
    verify.mockRejectedValue(apiErrors.forbidden("This API key is not allowed to do that."));
    const handler = vi.fn();
    const response = await ingestRoute(
      { scope: "ingest:wazuh" },
      handler,
    )(apiRequest("/api/x", { method: "POST", headers: { authorization: `Bearer ${KEY}` } }));
    expect(response.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("POST /api/ingest/wazuh", () => {
  it("records a batch and answers with what happened, without echoing the alerts", async () => {
    const response = await post({ alerts: [bruteForce, logon] });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toEqual({
      success: true,
      data: { received: 2, ...SUMMARY, rejected: [] },
      error: null,
    });
    expect(verify).toHaveBeenCalledWith(KEY, "ingest:wazuh");
    expect(store).toHaveBeenCalledTimes(1);
    const [source, records] = store.mock.calls[0];
    expect(source).toBe("wazuh");
    expect(records.map((record: { event_type: string }) => record.event_type)).toEqual([
      "authentication_failures",
      "authentication_success",
    ]);
    expect(JSON.stringify(body)).not.toContain(KEY);
  });

  it("audits one entry for the batch: who sent it and the counts, never the alerts", async () => {
    await post({ alerts: [bruteForce, logon] });

    expect(audit).toHaveBeenCalledTimes(1);
    const [entry] = audit.mock.calls[0];
    expect(entry).toMatchObject({
      action: "ingest.batch",
      userId: null,
      entityType: "api_key",
      entityId: PRINCIPAL.keyId,
      metadata: {
        source: "wazuh",
        key_name: "Wazuh lab",
        key_prefix: "arc_KKKK",
        owner_id: PRINCIPAL.ownerId,
        received: 2,
        accepted: 2,
        rejected: 0,
        ...SUMMARY,
      },
    });
    const text = JSON.stringify(entry);
    for (const secret of ["administrator", "198.51.100.99", "full_log", "SAMPLE-WIN10", KEY])
      expect(text).not.toContain(secret);
  });

  it("a bad alert in the batch is rejected on its own, with its position and a reason", async () => {
    const response = await post({ alerts: [bruteForce, "junk", { rule: {} }] });
    const { data } = await response.json();

    expect(response.status).toBe(200);
    expect(store.mock.calls[0][1]).toHaveLength(1);
    expect(data.received).toBe(3);
    expect(data.rejected.map((r: { index: number }) => r.index)).toEqual([1, 2]);
    expect(data.rejected[0].reason).toMatch(/Not a Wazuh alert/);
    expect(audit.mock.calls[0][0].metadata).toMatchObject({
      received: 3,
      accepted: 1,
      rejected: 2,
    });
  });

  it("a batch with nothing usable stores nothing but is still answered and audited", async () => {
    const response = await post({ alerts: ["junk"] });
    const { data } = await response.json();
    expect(response.status).toBe(200);
    expect(store).not.toHaveBeenCalled();
    expect(data).toMatchObject({
      received: 1,
      events_created: 0,
      alerts_created: 0,
      duplicates: 0,
    });
    expect(data.rejected).toHaveLength(1);
    expect(audit).toHaveBeenCalledTimes(1);
  });

  it("is refused without a valid key, and nothing is read or stored", async () => {
    verify.mockRejectedValue(apiErrors.unauthenticated("The API key is not valid."));
    const response = await POST(
      apiRequest("/api/ingest/wazuh", { body: { alerts: [bruteForce] } }),
    );
    expect(response.status).toBe(401);
    expect(store).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it.each([
    ["a body that is not JSON", "{not json", {}, 400],
    ["an empty body", "", { "content-type": "application/json" }, 400],
    ["a body that is not JSON by its type", "alerts=1", { "content-type": "text/plain" }, 415],
    ["no alerts", { alerts: [] }, {}, 422],
    ["no alerts field", {}, {}, 422],
    ["a list instead of an object", [bruteForce], {}, 422],
    ["a field it does not know", { alerts: [bruteForce], api_key: "x" }, {}, 422],
    ["more than a hundred alerts", { alerts: Array(101).fill(bruteForce) }, {}, 422],
  ])("refuses %s (%i)", async (_name, body, headers, status) => {
    const response = await post(body, headers as Record<string, string>);
    expect(response.status).toBe(status);
    expect(store).not.toHaveBeenCalled();
    expect((await response.json()).success).toBe(false);
  });

  it("refuses a body over 1 MiB (413), whether or not it says how long it is", async () => {
    const huge = JSON.stringify({ alerts: [{ full_log: "x".repeat(1024 * 1024 + 10) }] });
    const declared = await post(huge, { "content-length": String(huge.length) });
    expect(declared.status).toBe(413);
    const undeclared = await post(huge);
    expect(undeclared.status).toBe(413);
    expect(store).not.toHaveBeenCalled();
  });

  it("accepts a batch of exactly a hundred", async () => {
    const response = await post({ alerts: Array(100).fill(logon) });
    expect(response.status).toBe(200);
    expect(store.mock.calls[0][1]).toHaveLength(100);
  });

  it("passes a refusal by the database on as a validation error, and hides anything unexpected", async () => {
    store.mockRejectedValue(
      apiErrors.validation(
        undefined,
        "The batch was refused: a record has a value that cannot be stored.",
      ),
    );
    const refused = await post({ alerts: [bruteForce] });
    expect(refused.status).toBe(422);
    expect(audit).not.toHaveBeenCalled(); // nothing was recorded, so nothing is audited as received

    store.mockRejectedValue(new Error("relation events does not exist"));
    const broken = await post({ alerts: [bruteForce] });
    expect(broken.status).toBe(500);
    expect(JSON.stringify(await broken.json())).not.toContain("relation");
  });
});

describe("ingestBatch", () => {
  const request = { headers: new Headers() };

  it("normalizes, stores once and reports counts next to what was rejected", async () => {
    const deps = {
      store: vi.fn().mockResolvedValue(SUMMARY),
      audit: vi.fn().mockResolvedValue(true),
    };
    const result = await ingestBatch(PRINCIPAL, wazuhSource, [bruteForce, 42], request, deps);
    expect(deps.store).toHaveBeenCalledWith("wazuh", expect.any(Array));
    expect(result).toMatchObject({ received: 2, ...SUMMARY });
    expect(result.rejected).toEqual([
      { index: 1, reason: expect.stringContaining("Not a Wazuh alert") },
    ]);
  });

  it("does not report a batch as handled when storing it failed", async () => {
    const deps = { store: vi.fn().mockRejectedValue(new Error("down")), audit: vi.fn() };
    await expect(ingestBatch(PRINCIPAL, wazuhSource, [bruteForce], request, deps)).rejects.toThrow(
      "down",
    );
    expect(deps.audit).not.toHaveBeenCalled();
  });
});

describe("source health", () => {
  const NOW = new Date("2026-09-27T12:00:00.000Z");
  const minutesAgo = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000).toISOString();
  const health = (overrides: Partial<SourceHealth>): SourceHealth => ({
    source: "wazuh",
    origin: "external",
    last_event_at: minutesAgo(5),
    last_received_at: minutesAgo(3),
    events_total: 10,
    events_24h: 4,
    alerts_total: 2,
    assets_total: 1,
    ...overrides,
  });

  it("is receiving within a quarter of an hour, quiet after that, and never claims more", () => {
    expect(statusOf({ origin: "external", last_received_at: minutesAgo(0) }, NOW)).toBe(
      "receiving",
    );
    expect(statusOf({ origin: "external", last_received_at: minutesAgo(15) }, NOW)).toBe(
      "receiving",
    );
    expect(statusOf({ origin: "external", last_received_at: minutesAgo(16) }, NOW)).toBe("quiet");
    expect(statusOf({ origin: "external", last_received_at: minutesAgo(60 * 24 * 3) }, NOW)).toBe(
      "quiet",
    );
    expect(statusOf({ origin: "external", last_received_at: null }, NOW)).toBe("never");
  });

  it("calls a demo feed demo, however recent it is: sample data is not a live connection", () => {
    expect(statusOf({ origin: "demo", last_received_at: minutesAgo(0) }, NOW)).toBe("demo");
  });

  it("always lists the Wazuh connector, even before its first event", () => {
    const cards = buildSourceCards([], NOW);
    expect(cards).toEqual([
      expect.objectContaining({
        id: "wazuh",
        name: "Wazuh",
        status: "never",
        origin: null,
        events_total: 0,
        last_received_at: null,
      }),
    ]);
  });

  it("puts live connectors first, then other live sources, then the demo feeds by name", () => {
    const cards = buildSourceCards(
      [
        health({ source: "demo-idp", origin: "demo" }),
        health({ source: "wazuh", last_received_at: minutesAgo(90) }),
        health({ source: "demo-edr", origin: "demo" }),
        health({ source: "other-sensor" }),
      ],
      NOW,
    );
    expect(cards.map((card) => `${card.id}:${card.status}`)).toEqual([
      "wazuh:quiet",
      "other-sensor:receiving",
      "demo-edr:demo",
      "demo-idp:demo",
    ]);
    expect(cards[0]).toMatchObject({
      events_total: 10,
      events_24h: 4,
      alerts_total: 2,
      assets_total: 1,
      origin: "external",
    });
  });

  it("does not mistake a demo feed named wazuh for the real connector", () => {
    const cards = buildSourceCards([health({ source: "wazuh", origin: "demo" })], NOW);
    expect(cards.map((card) => `${card.id}:${card.status}:${card.origin}`)).toEqual([
      "wazuh:never:null",
      "wazuh:demo:demo",
    ]);
  });
});

describe("formatRelative", () => {
  const NOW = new Date("2026-09-27T12:00:00.000Z");
  const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000).toISOString();

  it("says how long ago in words, the way a person would", () => {
    expect(formatRelative(ago(0), NOW)).toBe("just now");
    expect(formatRelative(ago(59), NOW)).toBe("just now");
    expect(formatRelative(ago(60), NOW)).toBe("1 minute ago");
    expect(formatRelative(ago(3 * 60 + 20), NOW)).toBe("3 minutes ago");
    expect(formatRelative(ago(59 * 60), NOW)).toBe("59 minutes ago");
    expect(formatRelative(ago(60 * 60), NOW)).toBe("1 hour ago");
    expect(formatRelative(ago(5 * 3600), NOW)).toBe("5 hours ago");
    expect(formatRelative(ago(47 * 3600), NOW)).toBe("47 hours ago");
    expect(formatRelative(ago(48 * 3600), NOW)).toBe("2 days ago");
    expect(formatRelative(ago(30 * 86400), NOW)).toBe("30 days ago");
  });

  it("reads a time in the future, from a clock that runs ahead, as just now", () => {
    expect(formatRelative(ago(-600), NOW)).toBe("just now");
  });
});

describe("list queries", () => {
  it("default to the newest first and refuse values that are not on the lists", () => {
    expect(eventListQuerySchema.parse({})).toMatchObject({
      sort: "occurred_at",
      order: "desc",
      page: 1,
    });
    expect(assetListQuerySchema.parse({})).toMatchObject({ sort: "last_seen", order: "desc" });
    expect(eventListQuerySchema.parse({ source: "", severity: "" })).toMatchObject({
      source: undefined,
      severity: undefined,
    });
    for (const bad of [
      { severity: "urgent" },
      { origin: "imported" },
      { asset: "nope" },
      { sort: "title" },
      { order: "sideways" },
    ]) {
      expect(eventListQuerySchema.safeParse(bad).success).toBe(false);
    }
    expect(assetListQuerySchema.safeParse({ sort: "os" }).success).toBe(false);
  });

  it("fall back to the defaults for a hand-edited address", () => {
    const { query, ignoredInvalid } = parseEventListParams({ severity: "urgent", page: "2" });
    expect(ignoredInvalid).toBe(true);
    expect(query.page).toBe(1);
  });
});

describe("the proxy", () => {
  it("leaves the ingest endpoints alone (no session to refresh, no login to redirect to) but not other API routes or pages", () => {
    const matcher = new RegExp(`^${proxyConfig.matcher[0]}$`);
    expect(matcher.test("/api/ingest/wazuh")).toBe(false);
    expect(matcher.test("/api/health")).toBe(false);
    expect(matcher.test("/api/indicators")).toBe(true);
    expect(matcher.test("/api/api-keys")).toBe(true);
    expect(matcher.test("/dashboard")).toBe(true);
    expect(matcher.test("/telemetry")).toBe(true);
  });
});
