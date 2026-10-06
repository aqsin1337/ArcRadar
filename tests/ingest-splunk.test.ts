import { describe, expect, it, vi } from "vitest";
import samples from "../scripts/fixtures/splunk-sample-alerts.json";
import { API_KEY_SCOPES, SCOPE_PERMISSIONS } from "@/lib/api-keys/constants";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import { ingestBatch } from "@/lib/telemetry/service";
import {
  normalizeSplunkAlert,
  parseSplunkTime,
  splunkBatchSchema,
  splunkSource,
} from "@/lib/telemetry/splunk";
import { TELEMETRY_SOURCES } from "@/lib/telemetry/constants";
import type { NormalizedRecord } from "@/lib/telemetry/types";

const item = (overrides: Record<string, unknown> = {}) => ({
  sid: "scheduler__admin__arcradar_rules__RMD5abc_at_1_3",
  search_name: "arcradar_1000",
  results_link: "https://splunk.example/app/search/@go?sid=abc",
  server_host: "splunk-lab",
  result: {
    _time: "1791288000.000",
    host: "WIN10-LAB",
    Source_Network_Address: "203.0.113.45",
    count: "7",
  },
  configuration: {
    rule_key: "1000",
    name: "Brute force from one address",
    severity: "high",
    mitre: "T1110, T1078",
  },
  ...overrides,
});

const record = (raw: unknown) => normalizeSplunkAlert(raw, 0) as NormalizedRecord;

describe("normalizeSplunkAlert", () => {
  it("turns a triggered saved search into an event and an alert", () => {
    const r = record(item());
    expect(r).toMatchObject({
      event_type: "splunk_alert",
      title: "Brute force from one address",
      severity: "high",
      occurred_at: "2026-10-06T12:00:00.000Z",
      alert: { create: true, technique_ids: ["T1110", "T1078"] },
      asset: { external_id: "WIN10-LAB", name: "WIN10-LAB", ip_address: null, os: null },
    });
    expect(r.description).toContain("Splunk rule 1000 (high) on WIN10-LAB.");
    expect(r.description).toContain("MITRE ATT&CK: T1110, T1078.");
    expect(r.payload).toMatchObject({ search_name: "arcradar_1000", result: { count: "7" } });
  });

  it("builds an id from the search name, the search id and the result, so two rows differ", () => {
    const a = record(item());
    const b = record(
      item({ result: { host: "WIN10-LAB", Source_Network_Address: "203.0.113.46" } }),
    );
    expect(a.source_event_id).toMatch(
      /^arcradar_1000:scheduler__admin__arcradar_rules__RMD5abc_at_1_3:[0-9a-f]{16}$/,
    );
    expect(a.source_event_id).not.toBe(b.source_event_id);
    expect(record(item()).source_event_id).toBe(a.source_event_id);
    expect(a.source_event_id.length).toBeLessThanOrEqual(200);
  });

  it("is not affected by the order of the result's fields", () => {
    const a = record(item({ result: { a: "1", b: "2" } }));
    const b = record(item({ result: { b: "2", a: "1" } }));
    expect(a.source_event_id).toBe(b.source_event_id);
  });

  it("takes the public source address as the indicator and leaves private ones out", () => {
    expect(record(item()).indicators).toEqual([{ type: "ipv4", value: "203.0.113.45" }]);
    expect(
      record(item({ result: { host: "H", Source_Network_Address: "192.168.1.5" } })).indicators,
    ).toEqual([]);
  });

  it("finds a destination address, a hash and a URL among the result's fields", () => {
    const sha = "a".repeat(64);
    const r = record(
      item({
        result: {
          host: "H",
          dest_ip: "198.51.100.9",
          SHA256: sha.toUpperCase(),
          url: "http://bad.example/x",
        },
      }),
    );
    expect(r.indicators).toEqual([
      { type: "ipv4", value: "198.51.100.9" },
      { type: "sha256", value: sha },
      { type: "url", value: "http://bad.example/x" },
    ]);
  });

  it("falls back to medium severity and a generic title when the parameters are missing or odd", () => {
    const bare = record(item({ configuration: undefined }));
    expect(bare.severity).toBe("medium");
    expect(bare.title).toBe("Splunk alert arcradar_1000");
    expect(bare.alert.technique_ids).toEqual([]);
    expect(
      record(item({ configuration: { severity: "urgent", mitre: "not-a-technique" } })),
    ).toMatchObject({
      severity: "medium",
      alert: { technique_ids: [] },
    });
  });

  it("has no asset when the result names no host", () => {
    expect(record(item({ result: { Source_Network_Address: "203.0.113.45" } })).asset).toBeNull();
  });

  it("uses the time of receipt when the result has no usable _time", () => {
    const before = Date.now();
    const r = record(item({ result: { host: "H" } }));
    expect(Date.parse(r.occurred_at)).toBeGreaterThanOrEqual(before - 1000);
  });

  it("rejects an item that is not a Splunk alert, with a reason that never echoes values", () => {
    for (const bad of [
      "junk",
      null,
      {},
      { sid: "x" },
      item({ search_name: "" }),
      item({ result: "x" }),
    ]) {
      const result = normalizeSplunkAlert(bad, 3);
      expect(result).toMatchObject({ index: 3 });
      expect("reason" in result).toBe(true);
    }
  });

  it("keeps a huge result within the payload limit and says it was cut", () => {
    const big = Object.fromEntries(
      Array.from({ length: 200 }, (_, i) => [`f${i}`, "x".repeat(500)]),
    );
    const r = record(item({ result: { host: "H", ...big } }));
    expect(JSON.stringify(r.payload).length).toBeLessThan(17 * 1024);
    expect(r.payload.truncated).toBeDefined();
  });

  it("removes characters the database cannot hold", () => {
    const r = record(item({ configuration: { name: "bad\u0000name", severity: "low" } }));
    expect(r.title).toBe("badname");
  });
});

describe("parseSplunkTime", () => {
  it("reads epoch seconds and ISO 8601, and nothing else", () => {
    expect(parseSplunkTime("1791288000.000")).toBe("2026-10-06T12:00:00.000Z");
    expect(parseSplunkTime(1791288000)).toBe("2026-10-06T12:00:00.000Z");
    expect(parseSplunkTime("2026-10-06T10:40:00.000+0000")).toBe("2026-10-06T10:40:00.000Z");
    expect(parseSplunkTime("2026-10-06T12:40:00+02:00")).toBe("2026-10-06T10:40:00.000Z");
    expect(parseSplunkTime("yesterday")).toBeNull();
    expect(parseSplunkTime("12")).toBeNull();
    expect(parseSplunkTime(undefined)).toBeNull();
  });
});

describe("splunkSource and the batch", () => {
  it("collects usable items and lists the others as rejected, never failing the batch", () => {
    const parsed = splunkSource.parse([item(), "junk", item({ sid: "other" })]);
    expect(parsed.records).toHaveLength(2);
    expect(parsed.rejected).toEqual([
      { index: 1, reason: expect.stringContaining("Not a Splunk alert") },
    ]);
  });

  it("the shipped sample file is accepted as is", () => {
    const parsed = splunkSource.parse(samples);
    expect(parsed.rejected).toEqual([]);
    expect(parsed.records.map((r) => r.severity)).toEqual(["high", "critical"]);
    expect(parsed.records[0].alert.technique_ids).toEqual(["T1110"]);
  });

  it("the request body takes 1 to 100 alerts and nothing else", () => {
    expect(splunkBatchSchema.safeParse({ alerts: [item()] }).success).toBe(true);
    expect(splunkBatchSchema.safeParse({ alerts: [] }).success).toBe(false);
    expect(splunkBatchSchema.safeParse({ alerts: Array(101).fill(item()) }).success).toBe(false);
    expect(splunkBatchSchema.safeParse({ alerts: [item()], extra: 1 }).success).toBe(false);
  });

  it("is stored under the splunk source and audited once, without the alerts themselves", async () => {
    const store = vi.fn().mockResolvedValue({
      events_created: 1,
      alerts_created: 1,
      duplicates: 0,
      assets_created: 1,
      indicators_created: 1,
    });
    const audit = vi.fn().mockResolvedValue(true);
    const principal: ApiKeyPrincipal = {
      keyId: "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d",
      keyName: "Splunk lab",
      keyPrefix: "arc_KKKK",
      ownerId: "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69",
      scopes: ["ingest:splunk"],
    };
    const result = await ingestBatch(
      principal,
      splunkSource,
      [item(), "junk"],
      { headers: new Headers() },
      { store, audit },
    );
    expect(store).toHaveBeenCalledWith("splunk", expect.any(Array));
    expect(result).toMatchObject({ received: 2, events_created: 1, rejected: [{ index: 1 }] });
    expect(audit).toHaveBeenCalledTimes(1);
    const entry = JSON.stringify(audit.mock.calls[0][0]);
    expect(entry).toContain('"source":"splunk"');
    expect(entry).not.toContain("203.0.113.45");
  });
});

describe("the key scope", () => {
  it("exists, and needs the same permission as the Wazuh one", () => {
    expect(API_KEY_SCOPES).toContain("ingest:splunk");
    expect(SCOPE_PERMISSIONS["ingest:splunk"]).toBe(SCOPE_PERMISSIONS["ingest:wazuh"]);
  });

  it("Splunk is a known source on the Telemetry page", () => {
    expect(TELEMETRY_SOURCES.map((s) => s.id)).toContain("splunk");
  });
});
