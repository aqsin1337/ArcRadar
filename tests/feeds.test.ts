import { describe, expect, it, vi } from "vitest";
import { parseKevCatalog } from "@/lib/feeds/kev";
import {
  MAX_ENTRIES_PER_FEED,
  parseFeodoJson,
  parseThreatFoxJson,
  parseUrlhausText,
  THREATFOX_MIN_CONFIDENCE,
} from "@/lib/feeds/parse";
import { runFeedImport, type FeedDeps, type FeedGroup } from "@/lib/feeds/import";
import { ProviderError } from "@/lib/intel/types";

const NOW = new Date("2026-09-30T06:00:00.000Z");

describe("parseUrlhausText", () => {
  it("keeps http(s) URLs, skips comments, blanks, junk, credentials and duplicates", () => {
    const text = [
      "# abuse.ch URLhaus",
      "",
      "http://198.51.100.9:8080/bin.sh",
      "https://evil.example/a?x=1",
      "http://198.51.100.9:8080/bin.sh",
      "ftp://evil.example/file",
      "http://user:pass@evil.example/x",
      "not a url",
    ].join("\r\n");
    const records = parseUrlhausText(text, NOW);
    expect(records.map((r) => r.value)).toEqual([
      "http://198.51.100.9:8080/bin.sh",
      "https://evil.example/a?x=1",
    ]);
    expect(records[0]).toMatchObject({
      type: "url",
      verdict: "malicious",
      severity: "high",
      confidence: 85,
      seen_at: NOW.toISOString(),
    });
    expect(records[0].description).toContain("URLhaus");
  });

  it("caps one import at the per-feed limit", () => {
    const text = Array.from(
      { length: MAX_ENTRIES_PER_FEED + 50 },
      (_, n) => `http://h${n}.example/x`,
    ).join("\n");
    expect(parseUrlhausText(text, NOW)).toHaveLength(MAX_ENTRIES_PER_FEED);
  });
});

describe("parseFeodoJson", () => {
  it("maps botnet servers, using the last time they were online", () => {
    const records = parseFeodoJson(
      [
        {
          ip_address: "50.16.16.211",
          port: 443,
          status: "online",
          malware: "QakBot",
          first_seen: "2025-12-30 13:56:31",
          last_online: "2026-03-12",
        },
        {
          ip_address: "162.243.103.246",
          port: 8080,
          status: "offline",
          malware: "Emotet",
          first_seen: "2022-06-04 21:24:53",
        },
      ],
      NOW,
    );
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({
      type: "ipv4",
      value: "50.16.16.211",
      verdict: "malicious",
      confidence: 95,
      seen_at: "2026-03-12T00:00:00.000Z",
    });
    expect(records[0].description).toContain("QakBot");
    expect(records[0].description).toContain("port 443");
    expect(records[1]).toMatchObject({ confidence: 80, seen_at: "2022-06-04T21:24:53.000Z" });
  });

  it("drops private addresses, junk and duplicates, and survives a non-array", () => {
    const records = parseFeodoJson(
      [
        { ip_address: "10.0.0.5" },
        { ip_address: "192.168.1.1" },
        { ip_address: "not-an-ip" },
        { ip_address: 5 },
        null,
        { ip_address: "50.16.16.211" },
        { ip_address: "50.16.16.211" },
      ],
      NOW,
    );
    expect(records.map((r) => r.value)).toEqual(["50.16.16.211"]);
    expect(parseFeodoJson({ not: "an array" }, NOW)).toEqual([]);
    expect(parseFeodoJson(null, NOW)).toEqual([]);
  });
});

describe("parseThreatFoxJson", () => {
  const entry = (over: Record<string, unknown>) => ({
    ioc_value: "evil.example",
    ioc_type: "domain",
    threat_type: "botnet_cc",
    malware_printable: "Cobalt Strike",
    confidence_level: 100,
    first_seen_utc: "2026-09-29 10:00:00",
    last_seen_utc: null,
    ...over,
  });

  it("maps every supported IOC type to an indicator type", () => {
    const sha256 = "a".repeat(64);
    const md5 = "b".repeat(32);
    const records = parseThreatFoxJson(
      {
        "1": [entry({ ioc_value: "45.9.148.7:8080", ioc_type: "ip:port" })],
        "2": [entry({ ioc_value: "Evil.Example", ioc_type: "domain" })],
        "3": [entry({ ioc_value: "https://evil.example/p", ioc_type: "url" })],
        "4": [entry({ ioc_value: sha256, ioc_type: "sha256_hash" })],
        "5": [entry({ ioc_value: md5, ioc_type: "md5_hash" })],
      },
      NOW,
    );
    expect(records.map((r) => [r.type, r.value]).sort()).toEqual(
      [
        ["ipv4", "45.9.148.7"],
        ["domain", "evil.example"],
        ["url", "https://evil.example/p"],
        ["sha256", sha256],
        ["md5", md5],
      ].sort(),
    );
    expect(records[0].description).toContain("Cobalt Strike");
    expect(records[0].description).toContain("botnet cc");
  });

  it("skips low confidence, unknown types, private addresses and bad values", () => {
    const records = parseThreatFoxJson(
      [
        entry({ confidence_level: THREATFOX_MIN_CONFIDENCE - 1 }),
        entry({ ioc_type: "envelope_id", ioc_value: "x" }),
        entry({ ioc_type: "ip:port", ioc_value: "192.168.0.4:80" }),
        entry({ ioc_type: "sha256_hash", ioc_value: "short" }),
        entry({ ioc_type: "url", ioc_value: "http://u:p@evil.example/" }),
        entry({ ioc_value: "" }),
        entry({ ioc_value: "kept.example" }),
      ],
      NOW,
    );
    expect(records.map((r) => r.value)).toEqual(["kept.example"]);
  });

  it("keeps the newest first, without duplicates, within the cap", () => {
    const many = Object.fromEntries(
      Array.from({ length: MAX_ENTRIES_PER_FEED + 20 }, (_, n) => [
        String(n),
        [
          entry({
            ioc_value: `h${n}.example`,
            first_seen_utc: new Date(Date.UTC(2026, 0, 1, 0, n)).toISOString(),
          }),
        ],
      ]),
    );
    many.dup = [entry({ ioc_value: "h5.example", first_seen_utc: "2020-01-01 00:00:00" })];
    const records = parseThreatFoxJson(many, NOW);
    expect(records).toHaveLength(MAX_ENTRIES_PER_FEED);
    expect(records[0].value).toBe(`h${MAX_ENTRIES_PER_FEED + 19}.example`);
    expect(new Set(records.map((r) => r.value)).size).toBe(records.length);
  });

  it("survives anything that is not the expected shape", () => {
    for (const input of [null, "text", 5, {}, { a: "not an array" }, []]) {
      expect(parseThreatFoxJson(input, NOW)).toEqual([]);
    }
  });
});

describe("parseKevCatalog", () => {
  const item = (over: Record<string, unknown>) => ({
    cveID: "CVE-2026-0001",
    vendorProject: "Example",
    product: "Widget",
    vulnerabilityName: "Example Widget Flaw",
    dateAdded: "2026-09-29",
    shortDescription: "Bad things.",
    requiredAction: "Patch.",
    knownRansomwareCampaignUse: "Unknown",
    notes: "https://vendor.example/advisory ; https://other.example/x.",
    ...over,
  });

  it("maps an entry: exploited in the wild, high, with references and the product", () => {
    const [record] = parseKevCatalog({ vulnerabilities: [item({})] });
    expect(record).toEqual({
      cve_id: "CVE-2026-0001",
      title: "Example Widget Flaw",
      description: "Bad things.",
      severity: "high",
      exploit_status: "exploited_in_wild",
      remediation: "Patch.",
      reference_urls: [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        "https://vendor.example/advisory",
        "https://other.example/x",
      ],
      published_at: "2026-09-29T00:00:00.000Z",
      affected_products: [{ vendor: "Example", product: "Widget" }],
    });
  });

  it("is critical when known to be used in ransomware campaigns", () => {
    const [record] = parseKevCatalog({
      vulnerabilities: [item({ knownRansomwareCampaignUse: "Known" })],
    });
    expect(record.severity).toBe("critical");
  });

  it("sorts newest first, drops duplicates and invalid ids, tolerates missing fields", () => {
    const records = parseKevCatalog({
      vulnerabilities: [
        item({ cveID: "CVE-2025-1111", dateAdded: "2025-01-01" }),
        item({ cveID: "cve-2026-2222", dateAdded: "2026-05-05" }),
        item({ cveID: "CVE-2026-2222" }),
        item({ cveID: "not-a-cve" }),
        { cveID: "CVE-2026-3333" },
        "garbage",
        null,
      ],
    });
    expect(records.map((r) => r.cve_id)).toEqual([
      "CVE-2026-2222",
      "CVE-2025-1111",
      "CVE-2026-3333",
    ]);
    const bare = records.find((r) => r.cve_id === "CVE-2026-3333");
    expect(bare).toMatchObject({
      title: "CVE-2026-3333",
      description: "",
      remediation: null,
      published_at: null,
      affected_products: [],
    });
  });

  it("returns nothing for a document that is not the catalog", () => {
    for (const input of [null, {}, { vulnerabilities: "no" }, []]) {
      expect(parseKevCatalog(input)).toEqual([]);
    }
  });
});

describe("runFeedImport", () => {
  const summary = (over: Partial<Record<string, number>> = {}) => ({
    created: 0,
    updated: 0,
    untouched: 0,
    skipped: 0,
    ...over,
  });

  function deps(over: Partial<FeedDeps> = {}) {
    const value: FeedDeps = {
      now: () => NOW,
      fetchText: vi.fn(async () => "http://evil.example/a\nhttp://evil.example/b"),
      fetchJson: vi.fn(async (definition) =>
        definition.id === "cisa_kev"
          ? {
              vulnerabilities: [
                { cveID: "CVE-2026-0001", vulnerabilityName: "Flaw", dateAdded: "2026-09-29" },
              ],
            }
          : definition.id === "feodo"
            ? [{ ip_address: "50.16.16.211", port: 443, status: "online", malware: "QakBot" }]
            : { "1": [{ ioc_value: "evil.example", ioc_type: "domain", confidence_level: 100 }] },
      ),
      recordIndicators: vi.fn(async () => summary({ created: 1 })),
      recordVulnerabilities: vi.fn(async () => summary({ created: 1 })),
      enabledGroups: vi.fn(async () => new Set<FeedGroup>(["abusech", "cisa_kev"])),
      markSynced: vi.fn(async () => undefined),
      ...over,
    };
    const audit = vi.fn().mockResolvedValue(true);
    return { deps: value, audit };
  }

  it("imports every feed, marks each group as synced and audits the run once", async () => {
    const { deps: d, audit } = deps();
    const results = await runFeedImport({ actor: "admin-1" }, d, audit);

    expect(results.map((r) => [r.feed, r.status, r.created])).toEqual([
      ["urlhaus", "ok", 1],
      ["feodo", "ok", 1],
      ["threatfox", "ok", 1],
      ["cisa_kev", "ok", 1],
    ]);
    expect(d.recordIndicators).toHaveBeenCalledTimes(3);
    expect(d.recordIndicators).toHaveBeenCalledWith("urlhaus", expect.any(Array));
    expect(d.recordVulnerabilities).toHaveBeenCalledTimes(1);
    expect(d.markSynced).toHaveBeenCalledWith("abusech");
    expect(d.markSynced).toHaveBeenCalledWith("cisa_kev");
    expect(audit).toHaveBeenCalledOnce();
    expect(audit.mock.calls[0][0]).toMatchObject({
      action: "feeds.imported",
      userId: "admin-1",
      metadata: { trigger: "manual" },
    });
  });

  it("runs only the requested groups", async () => {
    const { deps: d, audit } = deps();
    const results = await runFeedImport({ groups: ["cisa_kev"], actor: "a" }, d, audit);
    expect(results.map((r) => r.feed)).toEqual(["cisa_kev"]);
    expect(d.recordIndicators).not.toHaveBeenCalled();
  });

  it("skips a group an administrator paused, without touching the network", async () => {
    const { deps: d, audit } = deps({
      enabledGroups: vi.fn(async () => new Set<FeedGroup>(["cisa_kev"])),
    });
    const results = await runFeedImport({ actor: "a" }, d, audit);
    expect(results.filter((r) => r.status === "disabled").map((r) => r.feed)).toEqual([
      "urlhaus",
      "feodo",
      "threatfox",
    ]);
    expect(d.fetchText).not.toHaveBeenCalled();
    expect(d.markSynced).toHaveBeenCalledTimes(1);
    expect(d.markSynced).toHaveBeenCalledWith("cisa_kev");
  });

  it("isolates a failing feed: the others are imported, the failure carries a safe reason", async () => {
    const { deps: d, audit } = deps({
      fetchJson: vi.fn(async (definition) => {
        if (definition.id === "feodo")
          throw new ProviderError("unavailable", "The provider is unavailable.");
        if (definition.id === "threatfox")
          throw new Error("connect ECONNREFUSED 10.0.0.1 secret-token");
        return { vulnerabilities: [{ cveID: "CVE-2026-0001" }] };
      }),
    });
    const results = await runFeedImport({ actor: "a" }, d, audit);
    const byFeed = Object.fromEntries(results.map((r) => [r.feed, r]));
    expect(byFeed.urlhaus.status).toBe("ok");
    expect(byFeed.cisa_kev.status).toBe("ok");
    expect(byFeed.feodo).toMatchObject({ status: "failed", error: "The provider is unavailable." });
    expect(byFeed.threatfox).toMatchObject({
      status: "failed",
      error: "The feed could not be imported.",
    });
    expect(JSON.stringify(results)).not.toContain("secret-token");
  });

  it("treats a feed with no usable entries as a failure and does not record anything", async () => {
    const { deps: d, audit } = deps({
      fetchText: vi.fn(async () => "<html>503</html>"),
      fetchJson: vi.fn(async () => null),
    });
    const results = await runFeedImport({ actor: "a" }, d, audit);
    expect(results.every((r) => r.status === "failed")).toBe(true);
    expect(d.recordIndicators).not.toHaveBeenCalled();
    expect(d.recordVulnerabilities).not.toHaveBeenCalled();
    expect(d.markSynced).not.toHaveBeenCalled();
  });

  it("reports the counts the database returned", async () => {
    const { deps: d, audit } = deps({
      recordIndicators: vi.fn(async () =>
        summary({ created: 5, updated: 2, untouched: 1, skipped: 3 }),
      ),
    });
    const [first] = await runFeedImport({ groups: ["abusech"], actor: "a" }, d, audit);
    expect(first).toMatchObject({ fetched: 2, created: 5, updated: 2, untouched: 1, skipped: 3 });
  });
});
