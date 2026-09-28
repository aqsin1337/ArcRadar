import { describe, expect, it } from "vitest";
import samples from "../scripts/fixtures/wazuh-sample-alerts.json";
import { MAX_PAYLOAD_BYTES } from "@/lib/telemetry/constants";
import { extractIndicators, isTrackableDomain, isTrackableIp } from "@/lib/telemetry/extract";
import { boundPayload, cleanJson, cleanText, clip } from "@/lib/telemetry/sanitize";
import type { NormalizedRecord, Rejection } from "@/lib/telemetry/types";
import {
  normalizeWazuhAlert,
  parseWazuhTimestamp,
  severityForLevel,
  wazuhBatchSchema,
  wazuhSource,
} from "@/lib/telemetry/wazuh";

const [bruteForce, powershell, certutil, dns, integrity, logon] = samples as Record<
  string,
  unknown
>[];

function record(raw: unknown): NormalizedRecord {
  const result = normalizeWazuhAlert(raw, 0);
  if ("reason" in result) throw new Error(`rejected: ${result.reason}`);
  return result;
}

const rejection = (raw: unknown): Rejection => {
  const result = normalizeWazuhAlert(raw, 7);
  if (!("reason" in result)) throw new Error("expected a rejection");
  return result;
};

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

/** A minimal valid alert with overrides merged in. */
const alert = (overrides: Record<string, unknown> = {}) => ({
  id: "1.1",
  timestamp: "2026-09-26T10:00:00.000+0000",
  rule: { id: "1", level: 8, description: "A rule" },
  ...overrides,
});

describe("severityForLevel", () => {
  it.each([
    [0, "info"],
    [3, "info"],
    [4, "low"],
    [6, "low"],
    [7, "medium"],
    [9, "medium"],
    [10, "high"],
    [12, "high"],
    [13, "critical"],
    [15, "critical"],
  ] as const)("level %i is %s", (level, severity) => {
    expect(severityForLevel(level)).toBe(severity);
  });
});

describe("parseWazuhTimestamp", () => {
  it("reads Wazuh's colon-less offset and standard ISO, and answers in UTC", () => {
    expect(parseWazuhTimestamp("2026-09-26T10:00:00.789+0000")).toBe("2026-09-26T10:00:00.789Z");
    expect(parseWazuhTimestamp("2026-09-26T10:00:00Z")).toBe("2026-09-26T10:00:00.000Z");
    expect(parseWazuhTimestamp("2026-09-26T10:00:00+04:00")).toBe("2026-09-26T06:00:00.000Z");
    expect(parseWazuhTimestamp("2026-09-26T10:00:00.5-0530")).toBe("2026-09-26T15:30:00.500Z");
  });

  it.each([
    "",
    "yesterday",
    "2026-09-26",
    "2026-09-26 10:00:00",
    "2026-13-40T10:00:00Z",
    "10:00:00Z",
  ])("refuses %j", (value) => {
    expect(parseWazuhTimestamp(value)).toBeNull();
  });
});

describe("the sample alerts", () => {
  it("a Windows brute-force alert becomes an alert with the attacker as its indicator", () => {
    const result = record(bruteForce);
    expect(result).toMatchObject({
      source_event_id: "sample-manager:1790000000.1000001",
      occurred_at: "2026-09-26T10:00:00.000Z",
      event_type: "authentication_failures",
      title: "Multiple Windows logon failures (sample)",
      severity: "high",
      alert: { create: true, technique_ids: ["T1110"] },
      asset: {
        external_id: "001",
        name: "SAMPLE-WIN10",
        ip_address: "192.168.56.101",
        os: "Windows",
      },
      indicators: [{ type: "ipv4", value: "198.51.100.99" }],
    });
    expect(result.description).toBe(
      "Wazuh rule 60204 (level 10) on SAMPLE-WIN10 (192.168.56.101). Location: EventChannel. Groups: windows, windows_security, authentication_failures. MITRE ATT&CK: T1110.",
    );
    // The raw alert is kept, key by key, for the alert page.
    expect(result.payload.rule).toMatchObject({ id: "60204", level: 10 });
    expect(result.payload.full_log).toContain("4625");
    expect(result.payload.data).toBeDefined();
    expect(result.payload.unknown_field).toBeUndefined();
  });

  it("names a Sysmon event by its id, and takes the destination of a connection", () => {
    const result = record(powershell);
    expect(result.event_type).toBe("sysmon_event_3");
    expect(result.severity).toBe("high");
    expect(result.alert.technique_ids).toEqual(["T1059.001"]);
    // The destination comes first; the machine's own private address is not an indicator.
    expect(result.indicators).toEqual([{ type: "ipv4", value: "203.0.113.88" }]);
  });

  it("takes the file's digests from a Sysmon process event, strongest first", () => {
    const result = record(certutil);
    expect(result.event_type).toBe("sysmon_event_1");
    expect(result.severity).toBe("high");
    expect(result.indicators).toEqual([
      { type: "sha256", value: "3".repeat(64) },
      { type: "sha1", value: "1".repeat(40) },
      { type: "md5", value: "2".repeat(32) },
    ]);
  });

  it("takes the name that was looked up", () => {
    const result = record(dns);
    expect(result.event_type).toBe("sysmon_event_22");
    expect(result.severity).toBe("medium");
    expect(result.indicators).toEqual([
      { type: "domain", value: "update-check.sample-c2.example" },
    ]);
  });

  it("a file integrity alert carries the new digests", () => {
    const result = record(integrity);
    expect(result.event_type).toBe("file_integrity");
    expect(result.severity).toBe("medium");
    expect(result.alert.create).toBe(true); // level 7 is the threshold
    expect(result.asset).toMatchObject({ external_id: "002", os: null }); // no Windows data: the OS is not guessed
    expect(result.indicators.map((indicator) => indicator.type)).toEqual(["sha256", "sha1", "md5"]);
    expect(result.alert.technique_ids).toEqual(["T1565.001"]);
  });

  it("a low-level alert stays an event: no alert, and no indicators from routine noise", () => {
    const result = record(logon);
    expect(result.severity).toBe("info");
    expect(result.alert).toEqual({ create: false, technique_ids: [] });
    expect(result.indicators).toEqual([]);
  });
});

describe("what is an indicator", () => {
  it.each([
    "10.0.0.5",
    "172.16.4.4",
    "192.168.1.10",
    "127.0.0.1",
    "169.254.10.1",
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "255.255.255.255",
    "::1",
    "fe80::1",
    "fc00::1",
    "not-an-ip",
  ])("never %s (the sensor's own network)", (ip) => {
    expect(isTrackableIp(ip)).toBe(false);
  });

  it.each([
    "8.8.8.8",
    "45.33.32.156",
    "198.51.100.99",
    "203.0.113.5",
    "192.0.2.7",
    "2606:4700:4700::1111",
    "2001:db8::5",
  ])("%s is trackable (public, or a documentation address a lab simulates attacks from)", (ip) => {
    expect(isTrackableIp(ip)).toBe(true);
  });

  it.each([
    "printer.local",
    "host.lan",
    "db.internal",
    "localhost",
    "nas.home",
    "dc.corp",
    "x.localdomain",
    "1.0.0.127.in-addr.arpa",
    "abc.onion",
    "198.51",
    "",
    "-bad.example",
  ])("the name %j is not an indicator", (name) => {
    expect(isTrackableDomain(name)).toBe(false);
  });

  it.each(["evil-updates.com", "Login.EXAMPLE", "a.b.example.org", "cdn.sample.example."])(
    "the name %s is",
    (name) => {
      expect(isTrackableDomain(name)).toBe(true);
    },
  );

  it("orders them where it went, where it came from, the file, then the name, and caps and dedupes", () => {
    const found = extractIndicators({
      data: {
        srcip: "198.51.100.10",
        dstip: "203.0.113.20",
        url: "http://bad.example/x",
        sha256: "a".repeat(64),
        win: {
          eventdata: {
            destinationIp: "203.0.113.20", // same as dstip: once
            sourceIp: "198.51.100.11",
            ipAddress: "198.51.100.12",
            queryName: "Name.Example.",
            hashes: `MD5=${"b".repeat(32)}`,
          },
        },
      },
    });
    expect(found.map((indicator) => `${indicator.type}:${indicator.value}`)).toEqual([
      "ipv4:203.0.113.20",
      "ipv4:198.51.100.12",
      "ipv4:198.51.100.11",
      "ipv4:198.51.100.10",
      "sha256:" + "a".repeat(64), // five at most: the md5, the name and the URL do not fit
    ]);
  });

  it("uses only what looks like a real digest or a full URL", () => {
    expect(
      extractIndicators({
        data: {
          sha256: "not-a-hash",
          md5: "abc",
          url: "/index.php?id=1",
          win: { eventdata: { hashes: "SHA256=xyz,IMPHASH=" + "c".repeat(32) } },
        },
      }),
    ).toEqual([]);
    expect(extractIndicators({ data: { url: "https://x.example/a?b=c" } })).toEqual([
      { type: "url", value: "https://x.example/a?b=c" },
    ]);
  });

  it("copes with an alert that has no data at all", () => {
    expect(extractIndicators({})).toEqual([]);
    expect(extractIndicators({ data: "text", syscheck: 3 })).toEqual([]);
  });
});

describe("normalizeWazuhAlert", () => {
  it("puts the manager in front of the alert id, so ids from two managers cannot collide", () => {
    expect(record(alert({ manager: { name: "m1" } })).source_event_id).toBe("m1:1.1");
    expect(record(alert()).source_event_id).toBe("1.1");
    expect(record(alert({ id: 42 })).source_event_id).toBe("42");
  });

  it("titles an alert by its rule, with a fallback and a limit", () => {
    expect(record(alert({ rule: { id: "77", level: 8 } })).title).toBe("Wazuh rule 77");
    const long = record(alert({ rule: { id: "1", level: 8, description: "x".repeat(400) } })).title;
    expect(long).toHaveLength(300);
    expect(long.endsWith("…")).toBe(true);
  });

  it("keeps only real ATT&CK ids, upper-cased and unique", () => {
    const ids = record(
      alert({
        rule: { id: "1", level: 8, mitre: { id: ["t1110", "T1110", "T1059.001", "nope", "T12"] } },
      }),
    ).alert.technique_ids;
    expect(ids).toEqual(["T1110", "T1059.001"]);
    expect(
      record(alert({ rule: { id: "1", level: 8, mitre: { id: "T1078" } } })).alert.technique_ids,
    ).toEqual(["T1078"]);
  });

  it("keeps at most 20 techniques, the number the database accepts on one alert", () => {
    // Going over would make the database refuse the whole batch, not just this alert.
    const many = Array.from({ length: 30 }, (_, index) => `T${1000 + index}`);
    const ids = record(alert({ rule: { id: "1", level: 8, mitre: { id: many } } })).alert
      .technique_ids;
    expect(ids).toEqual(many.slice(0, 20));
  });

  it("makes an asset of the agent, and not of an alert without one", () => {
    expect(record(alert()).asset).toBeNull();
    expect(record(alert({ agent: { id: 3 } })).asset).toEqual({
      external_id: "3",
      name: "Agent 3",
      ip_address: null,
      os: null,
    });
    // "any" is what Wazuh writes for an agent that connects from anywhere: not an address.
    expect(
      record(alert({ agent: { id: "004", name: "HOST", ip: "any" } })).asset?.ip_address,
    ).toBeNull();
    expect(
      record(alert({ agent: { id: "004", name: "HOST", ip: "2001:db8::4" } })).asset?.ip_address,
    ).toBe("2001:db8::4");
  });

  it("names the event type after the last rule group when nothing is more specific", () => {
    expect(
      record(alert({ rule: { id: "1", level: 8, groups: ["web", "Web Attack!"] } })).event_type,
    ).toBe("web_attack_");
    expect(record(alert()).event_type).toBe("wazuh_alert");
  });

  it("creates an alert from level 7 up and only then reads indicators", () => {
    const data = { srcip: "198.51.100.5" };
    expect(record(alert({ rule: { id: "1", level: 6 }, data })).alert.create).toBe(false);
    expect(record(alert({ rule: { id: "1", level: 6 }, data })).indicators).toEqual([]);
    expect(record(alert({ rule: { id: "1", level: 7 }, data })).alert.create).toBe(true);
    expect(record(alert({ rule: { id: "1", level: "12" }, data })).severity).toBe("high"); // a level sent as text
  });

  it.each([
    ["something that is not an object", "text", "the alert"],
    ["no rule", { id: "1", timestamp: "2026-09-26T10:00:00Z" }, "rule"],
    ["no id", { timestamp: "2026-09-26T10:00:00Z", rule: { id: "1", level: 8 } }, "id"],
    ["no timestamp", { id: "1", rule: { id: "1", level: 8 } }, "timestamp"],
    ["a rule without a level", alert({ rule: { id: "1" } }), "rule.level"],
  ])("rejects %s, and says which field without echoing values", (_name, raw, field) => {
    const result = rejection(raw);
    expect(result.index).toBe(7);
    expect(result.reason).toContain("Not a Wazuh alert");
    expect(result.reason).toContain(field);
  });

  it("rejects a level outside 0-15, a bad timestamp and an unusable id, each on its own", () => {
    expect(rejection(alert({ rule: { id: "1", level: 16 } })).reason).toMatch(/level/);
    expect(rejection(alert({ rule: { id: "1", level: "high" } })).reason).toMatch(/level/);
    expect(rejection(alert({ rule: { id: "1", level: 7.5 } })).reason).toMatch(/level/);
    expect(rejection(alert({ timestamp: "yesterday" })).reason).toMatch(/timestamp/);
    expect(rejection(alert({ id: "   " })).reason).toMatch(/id/);
    expect(rejection(alert({ id: "x".repeat(201) })).reason).toMatch(/id/);
    expect(JSON.stringify([rejection(alert({ timestamp: "secret-value" }))])).not.toContain(
      "secret-value",
    );
  });
});

describe("bounding what is kept", () => {
  it("strips what the database cannot hold: NUL characters and lone surrogates", () => {
    expect(cleanText("a\u0000b")).toBe("ab");
    expect(cleanText("x\ud800y")).toBe("x�y");
    expect(cleanJson({ "k\u0000": ["v\u0000", { n: 1, ok: true, no: null }] })).toEqual({
      k: ["v", { n: 1, ok: true, no: null }],
    });
    const result = record(
      alert({ full_log: "log\u0000line", rule: { id: "1", level: 8, description: "de\u0000sc" } }),
    );
    expect(result.title).toBe("desc");
    expect(JSON.stringify(result.payload)).not.toContain("\\u0000");
  });

  it("clips text with an ellipsis", () => {
    expect(clip("  short  ", 10)).toBe("short");
    expect(clip("abcdefghij", 5)).toBe("abcd…");
  });

  it("leaves a small alert alone", () => {
    const small = { id: "1", rule: { id: "1", level: 8 }, full_log: "x" };
    expect(boundPayload(small)).toEqual(small);
  });

  it("drops the raw log first, then the decoded data, then all but the rule, and says so", () => {
    const base = {
      id: "1",
      timestamp: "t",
      rule: { id: "9", level: 12, description: "d", firedtimes: 3 },
    };
    const bigLog = boundPayload({ ...base, data: { a: 1 }, full_log: "L".repeat(20_000) });
    expect(bigLog.full_log).toBeUndefined();
    expect(bigLog.data).toEqual({ a: 1 });
    expect(bigLog.truncated).toEqual(["full_log"]);

    const bigData = boundPayload({
      ...base,
      data: { blob: "D".repeat(20_000) },
      full_log: "L".repeat(20_000),
    });
    expect(bigData.data).toEqual({ truncated: true });
    expect(bigData.truncated).toEqual(["full_log", "data"]);
    expect(bigData.rule).toBeDefined();

    const bigRule = boundPayload({
      ...base,
      rule: { ...base.rule, groups: Array(5000).fill("group-name") },
    });
    expect(bigRule).toMatchObject({
      rule: { id: "9", level: 12, description: "d" },
      truncated: ["everything but the rule"],
    });
    for (const result of [bigLog, bigData, bigRule])
      expect(bytes(result)).toBeLessThanOrEqual(MAX_PAYLOAD_BYTES);
  });

  it("a whole alert far over the limit is stored within it", () => {
    const result = record(
      alert({ full_log: "L".repeat(200_000), data: { blob: "D".repeat(200_000) } }),
    );
    expect(bytes(result.payload)).toBeLessThanOrEqual(MAX_PAYLOAD_BYTES);
    expect(result.payload.truncated).toBeDefined();
  });
});

describe("the request body", () => {
  it("is exactly { alerts: [1 to 100 items] }", () => {
    expect(wazuhBatchSchema.safeParse({ alerts: [{}] }).success).toBe(true);
    expect(wazuhBatchSchema.safeParse({ alerts: Array(100).fill({}) }).success).toBe(true);
    for (const body of [
      { alerts: [] },
      { alerts: Array(101).fill({}) },
      {},
      { alerts: "x" },
      { alert: [{}] },
      { alerts: [{}], key: "k" },
      [],
      null,
    ]) {
      expect(wazuhBatchSchema.safeParse(body).success).toBe(false);
    }
  });

  it("parses a mixed batch: usable alerts become records, the rest are rejected with their position", () => {
    const parsed = wazuhSource.parse([bruteForce, "junk", logon, { rule: {} }]);
    expect(parsed.records.map((r) => r.event_type)).toEqual([
      "authentication_failures",
      "authentication_success",
    ]);
    expect(parsed.rejected.map((r) => r.index)).toEqual([1, 3]);
    expect(wazuhSource.id).toBe("wazuh");
  });
});
