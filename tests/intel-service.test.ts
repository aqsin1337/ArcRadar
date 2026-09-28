import { describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { describeAttempt } from "@/lib/intel/messages";
import { DemoProvider } from "@/lib/intel/providers/demo";
import { parseTarget, type IntelTarget } from "@/lib/intel/target";
import { lookupIntel, type LookupDeps } from "@/lib/intel/service";
import { buildTimeline, type LocalContext } from "@/lib/intel/timeline";
import {
  ProviderError,
  type IntelProvider,
  type IpProfile,
  type ProviderAttempt,
  type ProviderInfo,
} from "@/lib/intel/types";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { RoleName } from "@/types/domain";

const NOW = new Date("2026-09-26T12:00:00.000Z");

const auth = (role: RoleName): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: `${role}@arcradar.test` },
  profile: { display_name: role, role },
  permissions: permissionsForRole(role),
});

const target = (kind: Parameters<typeof parseTarget>[0], value: string): IntelTarget => {
  const parsed = parseTarget(kind, value);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.target;
};

const emptyLocal: LocalContext = {
  indicator: null,
  related: [],
  alerts: [],
  events: [],
  investigations: [],
  timeline: [],
};

const liveInfo = (id: "virustotal" | "abuseipdb"): ProviderInfo => ({
  id,
  name: id === "virustotal" ? "VirusTotal" : "AbuseIPDB",
  origin: "external",
});

const liveProfile = (ip: string): IpProfile => ({
  kind: "ip",
  ip,
  version: 4,
  network: null,
  asn: 15169,
  organization: "Live Org",
  isp: null,
  usage_type: null,
  country: "US",
  region: null,
  city: null,
  hostnames: [],
  open_ports: [],
  related_domains: [],
  report_count: null,
  last_reported_at: null,
  retrieved_at: NOW.toISOString(),
  reputation: { verdict: "unknown", confidence: null, summary: "live" },
  detections: null,
  findings: [],
  tags: [],
  last_analysed_at: null,
});

/** A live provider whose IP lookup is `behaviour`. */
function liveProvider(
  id: "virustotal" | "abuseipdb",
  behaviour: (ip: string, signal: AbortSignal) => Promise<IpProfile | null>,
  kinds: ("ip" | "domain")[] = ["ip", "domain"],
) {
  const lookupIp = vi.fn((ip: string, context: { signal: AbortSignal }) =>
    behaviour(ip, context.signal),
  );
  const lookupDomain = vi.fn(async () => null);
  const provider: IntelProvider = {
    info: liveInfo(id),
    ...(kinds.includes("ip") ? { lookupIp } : {}),
    ...(kinds.includes("domain") ? { lookupDomain } : {}),
  };
  return { provider, lookupIp, lookupDomain };
}

function deps(external: IntelProvider[], overrides: Partial<LookupDeps> = {}) {
  const demo = new DemoProvider();
  const demoLookup = vi.spyOn(demo, "lookupIp");
  const audit = vi.fn().mockResolvedValue(true);
  const loadLocal = vi.fn().mockResolvedValue(emptyLocal);
  const value: LookupDeps = {
    registry: { external, demo },
    now: () => NOW,
    timeoutMs: 200,
    loadLocal,
    audit,
    ...overrides,
  };
  return { deps: value, audit, demoLookup, loadLocal };
}

const request = { headers: new Headers({ "x-forwarded-for": "198.51.100.5" }) };

describe("lookupIntel without any live provider", () => {
  it("answers from the demo provider, labelled demo, and records no audit entry", async () => {
    const { deps: d, audit } = deps([]);
    const result = await lookupIntel(auth("viewer"), target("ip", "198.51.100.23"), request, d);

    expect(result.results).toHaveLength(1);
    expect(result.results[0].provider).toEqual({
      id: "demo",
      name: "Demo dataset",
      origin: "demo",
    });
    expect(result.results[0].profile).toMatchObject({ kind: "ip", ip: "198.51.100.23" });
    expect(result.attempts).toEqual([{ provider: result.results[0].provider, status: "ok" }]);
    expect(result).toMatchObject({
      kind: "ip",
      value: "198.51.100.23",
      indicator_type: "ipv4",
      live_providers: [],
      live_allowed: false,
      fallback: false,
    });
    expect(audit).not.toHaveBeenCalled();
  });

  it("says so when even the demo dataset has no record", async () => {
    const { deps: d } = deps([]);
    const result = await lookupIntel(auth("analyst"), target("ip", "203.0.113.190"), request, d);
    expect(result.results).toEqual([]);
    expect(result.attempts).toEqual([
      { provider: expect.objectContaining({ id: "demo" }), status: "not_found" },
    ]);
    expect(result.live_allowed).toBe(true);
  });

  it("hands back what the workspace knows, whatever the providers say", async () => {
    const local = {
      ...emptyLocal,
      related: [
        {
          id: "i1",
          type: "domain" as const,
          value: "a.example",
          verdict: "malicious" as const,
          severity: "high" as const,
          origin: "demo" as const,
        },
      ],
    };
    const { deps: d, loadLocal } = deps([], { loadLocal: vi.fn().mockResolvedValue(local) });
    const result = await lookupIntel(auth("viewer"), target("ip", "192.0.2.10"), request, d);
    expect(result.local).toBe(local);
    expect(loadLocal).not.toHaveBeenCalled(); // the override replaced it
  });

  it("fails as a whole when the workspace data cannot be read", async () => {
    const { deps: d } = deps([], {
      loadLocal: vi.fn().mockRejectedValue(new Error("database down")),
    });
    await expect(
      lookupIntel(auth("viewer"), target("ip", "192.0.2.10"), request, d),
    ).rejects.toThrow("database down");
  });
});

describe("lookupIntel with live providers", () => {
  it("asks a live provider for an analyst, shows only its answer and audits the lookup", async () => {
    const vt = liveProvider("virustotal", async (ip) => liveProfile(ip));
    const { deps: d, audit, demoLookup } = deps([vt.provider]);
    const result = await lookupIntel(auth("analyst"), target("ip", "8.8.8.8"), request, d);

    expect(vt.lookupIp).toHaveBeenCalledOnce();
    expect(vt.lookupIp.mock.calls[0][0]).toBe("8.8.8.8");
    expect(demoLookup).not.toHaveBeenCalled();
    expect(result.results.map((entry) => entry.provider.id)).toEqual(["virustotal"]);
    expect(result.results[0].provider.origin).toBe("external");
    expect(result).toMatchObject({ fallback: false, live_allowed: true });
    expect(result.live_providers.map((provider) => provider.id)).toEqual(["virustotal"]);

    expect(audit).toHaveBeenCalledOnce();
    expect(audit).toHaveBeenCalledWith(
      {
        action: "intel.lookup",
        userId: "user-1",
        entityType: "intel",
        entityId: "8.8.8.8",
        metadata: { kind: "ip", providers: [{ provider: "virustotal", outcome: "ok" }] },
      },
      request,
    );
  });

  it("never asks a live provider for a viewer: demo answers and the reason is recorded", async () => {
    const vt = liveProvider("virustotal", async (ip) => liveProfile(ip));
    const { deps: d, audit } = deps([vt.provider]);
    const result = await lookupIntel(auth("viewer"), target("ip", "8.8.8.8"), request, d);

    expect(vt.lookupIp).not.toHaveBeenCalled();
    expect(result.attempts[0]).toEqual({
      provider: liveInfo("virustotal"),
      status: "skipped",
      reason: "not_permitted",
    });
    expect(result.results[0].provider.id).toBe("demo");
    expect(result).toMatchObject({ fallback: true, live_allowed: false });
    expect(audit).not.toHaveBeenCalled();
  });

  it("never sends private, reserved or credentialed subjects out, even for an analyst", async () => {
    const vt = liveProvider("virustotal", async (ip) => liveProfile(ip));
    const { deps: d, audit } = deps([vt.provider]);

    const documentation = await lookupIntel(
      auth("analyst"),
      target("ip", "198.51.100.23"),
      request,
      d,
    );
    expect(documentation.attempts[0]).toMatchObject({ status: "skipped", reason: "not_public" });
    expect(documentation.results[0].provider.id).toBe("demo");
    expect(documentation.fallback).toBe(true);

    const lookupUrl = vi.fn(async () => null);
    const urlProvider: IntelProvider = { info: liveInfo("virustotal"), lookupUrl };
    const { deps: urlDeps } = deps([urlProvider], { audit });
    const url = await lookupIntel(
      auth("analyst"),
      target("url", "https://user:pw@google.com/x"),
      request,
      urlDeps,
    );
    expect(url.attempts[0]).toMatchObject({ status: "skipped", reason: "has_credentials" });

    expect(vt.lookupIp).not.toHaveBeenCalled();
    expect(lookupUrl).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("falls back to demo data, flagged, when the live provider fails", async () => {
    const vt = liveProvider("virustotal", async () => {
      throw new ProviderError("rate_limited", "limit", 30);
    });
    const { deps: d, audit } = deps([vt.provider]);
    const result = await lookupIntel(auth("admin"), target("ip", "8.8.8.8"), request, d);

    expect(result.attempts[0]).toEqual({
      provider: liveInfo("virustotal"),
      status: "failed",
      reason: "rate_limited",
      retry_after_seconds: 30,
    });
    expect(result.attempts[1]).toMatchObject({ status: "ok", provider: { id: "demo" } });
    expect(result.results.map((entry) => entry.provider.origin)).toEqual(["demo"]);
    expect(result.fallback).toBe(true);
    expect(audit).toHaveBeenCalledOnce(); // the value was sent, even though the provider then failed
    expect(audit.mock.calls[0][0].metadata).toEqual({
      kind: "ip",
      providers: [{ provider: "virustotal", outcome: "failed" }],
    });
  });

  it("treats an unexpected error inside a provider as a failure, never as a crash", async () => {
    const vt = liveProvider("virustotal", async () => {
      throw new Error("boom: something with a secret");
    });
    const { deps: d } = deps([vt.provider]);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const result = await lookupIntel(auth("analyst"), target("ip", "8.8.8.8"), request, d);
    error.mockRestore();

    expect(result.attempts[0]).toMatchObject({ status: "failed", reason: "unavailable" });
    expect(JSON.stringify(result)).not.toContain("secret");
    expect(result.results[0].provider.id).toBe("demo");
  });

  it("keeps the answers of the providers that delivered and needs no demo data then", async () => {
    const vt = liveProvider("virustotal", async () => {
      throw new ProviderError("auth", "bad key");
    });
    const abuse = liveProvider("abuseipdb", async (ip) => liveProfile(ip), ["ip"]);
    const { deps: d, demoLookup } = deps([vt.provider, abuse.provider]);
    const result = await lookupIntel(auth("analyst"), target("ip", "8.8.8.8"), request, d);

    expect(result.results.map((entry) => entry.provider.id)).toEqual(["abuseipdb"]);
    expect(result.attempts.map((attempt) => attempt.status)).toEqual(["failed", "ok"]);
    expect(result.fallback).toBe(false);
    expect(demoLookup).not.toHaveBeenCalled();
  });

  it("asks providers in parallel", async () => {
    const started: string[] = [];
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const slow = (id: "virustotal" | "abuseipdb") =>
      liveProvider(id, async (ip) => {
        started.push(id);
        await gate;
        return liveProfile(ip);
      });
    const vt = slow("virustotal");
    const abuse = slow("abuseipdb");
    const { deps: d } = deps([vt.provider, abuse.provider], { timeoutMs: 5000 });

    const pending = lookupIntel(auth("analyst"), target("ip", "8.8.8.8"), request, d);
    await vi.waitFor(() => expect(started).toEqual(["virustotal", "abuseipdb"]));
    release();
    expect((await pending).results).toHaveLength(2);
  });

  it("gives providers a deadline and reports a timeout", async () => {
    const stuck = liveProvider(
      "virustotal",
      (_ip, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new ProviderError("timeout", "too slow")));
        }),
    );
    const { deps: d } = deps([stuck.provider], { timeoutMs: 20 });
    const result = await lookupIntel(auth("analyst"), target("ip", "8.8.8.8"), request, d);
    expect(result.attempts[0]).toMatchObject({ status: "failed", reason: "timeout" });
    expect(result.fallback).toBe(true);
  });

  it("only asks providers that can answer this kind of lookup", async () => {
    const abuse = liveProvider("abuseipdb", async (ip) => liveProfile(ip), ["ip"]);
    const { deps: d, audit } = deps([abuse.provider]);
    const result = await lookupIntel(auth("analyst"), target("domain", "google.com"), request, d);

    expect(result.live_providers).toEqual([]);
    expect(result.attempts.map((attempt) => attempt.provider.id)).toEqual(["demo"]);
    expect(abuse.lookupIp).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("keeps query strings and fragments of a URL out of the audit trail", async () => {
    const lookupUrl = vi.fn(async () => null);
    const provider: IntelProvider = { info: liveInfo("virustotal"), lookupUrl };
    const { deps: d, audit } = deps([provider]);
    await lookupIntel(
      auth("analyst"),
      target("url", "https://google.com/login?token=SECRET#frag"),
      request,
      d,
    );

    expect(lookupUrl).toHaveBeenCalledOnce();
    expect(audit.mock.calls[0][0].entityId).toBe("https://google.com/login");
    expect(JSON.stringify(audit.mock.calls[0][0])).not.toContain("SECRET");
  });
});

describe("describeAttempt", () => {
  const info = liveInfo("virustotal");
  const say = (attempt: ProviderAttempt) => describeAttempt(attempt);

  it("has a plain sentence for every outcome", () => {
    expect(say({ provider: info, status: "ok" })).toBe("Answered.");
    expect(say({ provider: info, status: "not_found" })).toMatch(/no record/);
    expect(say({ provider: info, status: "skipped", reason: "not_permitted" })).toMatch(/analysts/);
    expect(say({ provider: info, status: "skipped", reason: "not_public" })).toMatch(/never sent/);
    expect(say({ provider: info, status: "skipped", reason: "has_credentials" })).toMatch(
      /user name/,
    );
    expect(
      say({ provider: info, status: "failed", reason: "auth", retry_after_seconds: null }),
    ).toMatch(/API key/);
    expect(
      say({ provider: info, status: "failed", reason: "rate_limited", retry_after_seconds: 30 }),
    ).toMatch(/30 seconds/);
    expect(
      say({ provider: info, status: "failed", reason: "rate_limited", retry_after_seconds: null }),
    ).toMatch(/later/);
    expect(
      say({ provider: info, status: "failed", reason: "timeout", retry_after_seconds: null }),
    ).toMatch(/in time/);
    expect(
      say({ provider: info, status: "failed", reason: "unavailable", retry_after_seconds: null }),
    ).toMatch(/unavailable/);
    expect(
      say({ provider: info, status: "failed", reason: "bad_response", retry_after_seconds: null }),
    ).toMatch(/format/);
  });
});

describe("buildTimeline", () => {
  const indicator = {
    first_seen: "2026-08-01T00:00:00.000Z",
    last_seen: "2026-09-25T00:00:00.000Z",
    source: "demo-seed",
    origin: "demo",
  } as NonNullable<LocalContext["indicator"]>;

  it("merges sightings, events, alerts and investigations, newest first", () => {
    const timeline = buildTimeline({
      indicator,
      events: [
        {
          id: "e1",
          title: "Beacon seen",
          severity: "high",
          event_type: "network",
          occurred_at: "2026-09-20T00:00:00.000Z",
          origin: "demo",
        },
      ],
      alerts: [
        {
          id: "a1",
          title: "C2 beacon",
          severity: "critical",
          status: "false_positive",
          created_at: "2026-09-22T00:00:00.000Z",
          origin: "demo",
        },
      ],
      investigations: [
        {
          id: "v1",
          title: "Harbor Lights",
          status: "investigating",
          priority: "high",
          created_at: "2026-09-10T00:00:00.000Z",
          origin: "demo",
        },
      ],
    });

    expect(timeline.map((entry) => entry.kind)).toEqual([
      "last_seen",
      "alert",
      "event",
      "investigation",
      "first_seen",
    ]);
    expect(timeline[1]).toMatchObject({
      title: "C2 beacon",
      detail: "Alert · False positive",
      severity: "critical",
    });
    expect(timeline[3].detail).toBe("Investigation · Investigating, high priority");
    expect(timeline[4]).toMatchObject({ detail: "Source: demo-seed", origin: "demo" });
  });

  it("links alerts and investigations to their pages, and nothing else", () => {
    const timeline = buildTimeline({
      indicator,
      events: [
        {
          id: "e1",
          title: "Beacon seen",
          severity: "high",
          event_type: "network",
          occurred_at: "2026-09-20T00:00:00.000Z",
          origin: "demo",
        },
      ],
      alerts: [
        {
          id: "a1",
          title: "C2 beacon",
          severity: "critical",
          status: "new",
          created_at: "2026-09-22T00:00:00.000Z",
          origin: "demo",
        },
      ],
      investigations: [
        {
          id: "v1",
          title: "Harbor Lights",
          status: "open",
          priority: "high",
          created_at: "2026-09-10T00:00:00.000Z",
          origin: "demo",
        },
      ],
    });
    const hrefs = Object.fromEntries(timeline.map((entry) => [entry.kind, entry.href]));
    expect(hrefs).toEqual({
      last_seen: null,
      alert: "/alerts/a1",
      event: null,
      investigation: "/investigations/v1",
      first_seen: null,
    });
  });

  it("does not repeat a single sighting, and is empty for an untracked subject", () => {
    const once = buildTimeline({
      indicator: { ...indicator, last_seen: indicator.first_seen },
      events: [],
      alerts: [],
      investigations: [],
    });
    expect(once.map((entry) => entry.kind)).toEqual(["first_seen"]);
    expect(buildTimeline({ indicator: null, events: [], alerts: [], investigations: [] })).toEqual(
      [],
    );
  });

  it("is capped", () => {
    const alerts = Array.from({ length: 40 }, (_, n) => ({
      id: `a${n}`,
      title: `Alert ${n}`,
      severity: "low" as const,
      status: "new" as const,
      created_at: new Date(Date.UTC(2026, 8, 1, 0, n)).toISOString(),
      origin: "local" as const,
    }));
    expect(buildTimeline({ indicator: null, alerts, events: [], investigations: [] })).toHaveLength(
      25,
    );
  });
});
