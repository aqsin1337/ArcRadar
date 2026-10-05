import { describe, expect, it, vi } from "vitest";
import {
  candidatesFrom,
  enrichIngestedIndicators,
  MAX_RESEARCHED_PER_BATCH,
  targetFor,
  type EnrichDeps,
} from "@/lib/telemetry/enrich";
import type { NormalizedRecord } from "@/lib/telemetry/types";
import { researchLive } from "@/lib/intel/service";
import { DemoProvider } from "@/lib/intel/providers/demo";
import {
  ProviderError,
  type IntelProvider,
  type IpProfile,
  type ProviderInfo,
} from "@/lib/intel/types";
import type { IndicatorType } from "@/types/domain";

const NOW = new Date("2026-09-30T12:00:00.000Z");

const record = (
  indicators: { type: IndicatorType; value: string }[],
  create = true,
): NormalizedRecord => ({
  source_event_id: "m:1",
  occurred_at: NOW.toISOString(),
  event_type: "authentication_failed",
  title: "Multiple logon failures",
  description: null,
  severity: "high",
  payload: {},
  asset: null,
  alert: { create, technique_ids: [] },
  indicators,
});

const info = (id: "virustotal" | "abuseipdb"): ProviderInfo => ({
  id,
  name: id,
  origin: "external",
});

const profile = (ip: string, verdict: "malicious" | "unknown" = "malicious"): IpProfile =>
  ({
    kind: "ip",
    ip,
    version: 4,
    reputation: { verdict, confidence: verdict === "malicious" ? 90 : null, summary: `${verdict}` },
  }) as unknown as IpProfile;

/** A live provider whose IP lookup is `answer`. */
function provider(
  id: "virustotal" | "abuseipdb",
  answer: (ip: string) => Promise<IpProfile | null>,
): IntelProvider & { lookupIp: ReturnType<typeof vi.fn> } {
  const lookupIp = vi.fn((ip: string) => answer(ip));
  return { info: info(id), lookupIp } as never;
}

const PUBLIC = ["45.9.148.7", "45.9.148.8", "45.9.148.9", "45.9.148.10", "45.9.148.11"];

function deps(over: Partial<EnrichDeps> = {}, providers: IntelProvider[] = []) {
  const value: EnrichDeps = {
    registry: { external: providers, demo: new DemoProvider() },
    now: () => NOW,
    timeoutMs: 200,
    findUnresearched: vi.fn(
      async (items: readonly { type: IndicatorType; value: string }[]) =>
        new Set(items.map((i) => `${i.type}:${i.value}`)),
    ),
    disabledProviders: vi.fn(async () => new Set<string>()),
    research: researchLive,
    record: vi.fn(async () => ({ created: 0, updated: 1, untouched: 0, skipped: 0 })),
    audit: vi.fn().mockResolvedValue(true),
    ...over,
  };
  return value;
}

describe("targetFor and candidatesFrom", () => {
  it("turns an indicator into the lookup it would be, or nothing for a type that cannot be looked up", () => {
    expect(targetFor("ipv4", "45.9.148.7")?.kind).toBe("ip");
    expect(targetFor("ipv6", "2606:4700:4700::1111")?.kind).toBe("ip");
    expect(targetFor("domain", "evil.example.com")?.kind).toBe("domain");
    expect(targetFor("url", "http://evil.example.com/a")?.kind).toBe("url");
    expect(targetFor("sha256", "a".repeat(64))).toMatchObject({ kind: "hash", hashType: "sha256" });
    expect(targetFor("email", "a@b.example")).toBeNull();
    expect(targetFor("cve", "CVE-2021-44228")).toBeNull();
    expect(targetFor("ipv4", "not-an-ip")).toBeNull();
  });

  it("takes each distinct lookup-able indicator of the alerts of a batch once, in order", () => {
    const found = candidatesFrom([
      record([
        { type: "ipv4", value: "45.9.148.7" },
        { type: "email", value: "a@b.example" },
      ]),
      record([
        { type: "ipv4", value: "45.9.148.7" },
        { type: "domain", value: "evil.example.com" },
      ]),
      record([{ type: "ipv4", value: "45.9.148.99" }], false), // an event without an alert brings no indicator in
    ]);
    expect(found.map((c) => `${c.type}:${c.value}`)).toEqual([
      "ipv4:45.9.148.7",
      "domain:evil.example.com",
    ]);
  });
});

describe("enrichIngestedIndicators", () => {
  it("does nothing, and touches nothing, when no live provider is set up", async () => {
    const d = deps();
    const summary = await enrichIngestedIndicators(
      [record([{ type: "ipv4", value: PUBLIC[0] }])],
      undefined,
      d,
    );
    expect(summary).toMatchObject({ candidates: 1, researched: 0 });
    expect(d.findUnresearched).not.toHaveBeenCalled();
    expect(d.record).not.toHaveBeenCalled();
    expect(d.audit).not.toHaveBeenCalled();
  });

  it("researches an unresearched indicator at every live provider and records the worst verdict", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip, "malicious"));
    const abuse = provider("abuseipdb", async (ip) => profile(ip, "unknown"));
    const d = deps({}, [vt, abuse]);
    const summary = await enrichIngestedIndicators(
      [record([{ type: "ipv4", value: PUBLIC[0] }])],
      undefined,
      d,
    );

    expect(vt.lookupIp).toHaveBeenCalledOnce();
    expect(abuse.lookupIp).toHaveBeenCalledOnce();
    expect(d.record).toHaveBeenCalledWith("lookup:abuseipdb.virustotal", [
      expect.objectContaining({
        type: "ipv4",
        value: PUBLIC[0],
        verdict: "malicious",
        confidence: 90,
      }),
    ]);
    expect(summary.researched).toBe(1);
    expect(d.audit).toHaveBeenCalledOnce();
    expect((d.audit as ReturnType<typeof vi.fn>).mock.calls[0][0]).toMatchObject({
      action: "indicator.researched",
      userId: null,
      metadata: { trigger: "ingest", candidates: 1 },
    });
  });

  it("asks only about what nobody has researched yet", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip));
    const d = deps({ findUnresearched: vi.fn(async () => new Set([`ipv4:${PUBLIC[1]}`])) }, [vt]);
    await enrichIngestedIndicators(
      [
        record([
          { type: "ipv4", value: PUBLIC[0] },
          { type: "ipv4", value: PUBLIC[1] },
        ]),
      ],
      undefined,
      d,
    );
    expect(vt.lookupIp).toHaveBeenCalledOnce();
    expect(vt.lookupIp.mock.calls[0][0]).toBe(PUBLIC[1]);
  });

  it("researches at most a few per delivery, in the order the alerts named them", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip));
    const d = deps({}, [vt]);
    await enrichIngestedIndicators(
      [record(PUBLIC.map((value) => ({ type: "ipv4" as const, value })))],
      undefined,
      d,
    );
    expect(MAX_RESEARCHED_PER_BATCH).toBe(4);
    expect(vt.lookupIp.mock.calls.map((call) => call[0])).toEqual(PUBLIC.slice(0, 4));
  });

  it("does not spend a slot on an address that may not leave the workspace", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip));
    const d = deps({}, [vt]);
    await enrichIngestedIndicators(
      [
        record([
          { type: "ipv4", value: "203.0.113.5" }, // documentation range: a lab, never asked about
          ...PUBLIC.slice(0, 4).map((value) => ({ type: "ipv4" as const, value })),
        ]),
      ],
      undefined,
      d,
    );
    expect(vt.lookupIp.mock.calls.map((call) => call[0])).toEqual(PUBLIC.slice(0, 4));
  });

  it("marks an indicator every provider answered 'not found' for as researched, so it is not asked again", async () => {
    const vt = provider("virustotal", async () => null);
    const d = deps({}, [vt]);
    await enrichIngestedIndicators([record([{ type: "ipv4", value: PUBLIC[0] }])], undefined, d);
    expect(d.record).toHaveBeenCalledWith("lookup:virustotal", [
      expect.objectContaining({ value: PUBLIC[0], verdict: "unknown", severity: "low" }),
    ]);
  });

  it("records nothing when every provider failed, so a later delivery tries again", async () => {
    const vt = provider("virustotal", async () => {
      throw new ProviderError("rate_limited", "slow down", 60);
    });
    const d = deps({}, [vt]);
    const summary = await enrichIngestedIndicators(
      [record([{ type: "ipv4", value: PUBLIC[0] }])],
      undefined,
      d,
    );
    expect(d.record).not.toHaveBeenCalled();
    expect(summary.researched).toBe(0);
  });

  it("leaves out a provider an administrator switched off, and does nothing when none is left", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip));
    const abuse = provider("abuseipdb", async (ip) => profile(ip));
    const some = deps({ disabledProviders: vi.fn(async () => new Set(["virustotal"])) }, [
      vt,
      abuse,
    ]);
    await enrichIngestedIndicators([record([{ type: "ipv4", value: PUBLIC[0] }])], undefined, some);
    expect(vt.lookupIp).not.toHaveBeenCalled();
    expect(abuse.lookupIp).toHaveBeenCalledOnce();

    const all = deps(
      { disabledProviders: vi.fn(async () => new Set(["virustotal", "abuseipdb"])) },
      [vt, abuse],
    );
    const summary = await enrichIngestedIndicators(
      [record([{ type: "ipv4", value: PUBLIC[1] }])],
      undefined,
      all,
    );
    expect(summary.researched).toBe(0);
    expect(all.findUnresearched).not.toHaveBeenCalled();
  });

  it("never throws into the delivery it follows", async () => {
    const vt = provider("virustotal", async (ip) => profile(ip));
    const d = deps({ findUnresearched: vi.fn().mockRejectedValue(new Error("database down")) }, [
      vt,
    ]);
    await expect(
      enrichIngestedIndicators([record([{ type: "ipv4", value: PUBLIC[0] }])], undefined, d),
    ).resolves.toMatchObject({ researched: 0 });
  });
});
