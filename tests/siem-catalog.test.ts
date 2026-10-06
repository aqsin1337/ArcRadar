import { describe, expect, it, vi } from "vitest";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import {
  catalogBatchSchema,
  fieldPercent,
  sourcesFor,
  summarizeCatalog,
  type FieldCatalog,
} from "@/lib/siem-rules/catalog";

vi.mock("@/lib/siem-rules/catalog-repository", () => ({
  storeCatalog: vi.fn(),
  findCatalog: vi.fn(),
}));
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: vi.fn() }));

const { ingestCatalog } = await import("@/lib/siem-rules/catalog-service");

const catalog: FieldCatalog = {
  sources: [
    {
      index: "main",
      sourcetype: "WinEventLog:Security",
      events_sampled: 200,
      window_hours: 24,
      reported_at: "2026-10-06T10:00:00Z",
      fields: [
        {
          name: "EventCode",
          events_with_field: 200,
          distinct_values: 6,
          sample_values: ["4625", "4624", "4672", "4634"],
        },
        {
          name: "Source_Network_Address",
          events_with_field: 50,
          distinct_values: 2,
          sample_values: [],
        },
      ],
    },
    {
      index: "main",
      sourcetype: "XmlWinEventLog:Sysmon",
      events_sampled: 10,
      window_hours: 24,
      reported_at: "2026-10-06T10:00:00Z",
      fields: [
        { name: "Image", events_with_field: 10, distinct_values: 4, sample_values: ["a.exe"] },
      ],
    },
  ],
};

const source = (over: Record<string, unknown> = {}) => ({
  index: "main",
  sourcetype: "WinEventLog:Security",
  window_hours: 24,
  events_sampled: 100,
  fields: [{ name: "EventCode", count: 100, distinct: 5, values: ["4625"] }],
  ...over,
});

describe("catalogBatchSchema", () => {
  it("takes 1 to 50 sources and nothing else", () => {
    expect(catalogBatchSchema.safeParse({ sources: [source()] }).success).toBe(true);
    expect(catalogBatchSchema.safeParse({ sources: [] }).success).toBe(false);
    expect(catalogBatchSchema.safeParse({ sources: Array(51).fill(source()) }).success).toBe(false);
    expect(catalogBatchSchema.safeParse({ sources: [source()], extra: 1 }).success).toBe(false);
    expect(catalogBatchSchema.safeParse({ sources: [source({ extra: 1 })] }).success).toBe(false);
  });

  it("refuses an index or sourcetype that is not a plain name, and out-of-range numbers", () => {
    const bad = (over: Record<string, unknown>) =>
      catalogBatchSchema.safeParse({ sources: [source(over)] }).success;
    expect(bad({ index: "Main Index" })).toBe(false);
    expect(bad({ index: "main | delete" })).toBe(false);
    expect(bad({ sourcetype: "a b" })).toBe(false);
    expect(bad({ window_hours: 0 })).toBe(false);
    expect(bad({ window_hours: 721 })).toBe(false);
    expect(bad({ events_sampled: 0 })).toBe(false);
    expect(bad({ fields: Array(501).fill({ name: "a", count: 1 }) })).toBe(false);
    expect(bad({ fields: [{ name: "a", count: -1 }] })).toBe(false);
    expect(bad({ fields: [{ name: "a", count: 1, values: Array(21).fill("x") }] })).toBe(false);
  });

  it("lets a strange field name through: the database skips it, the batch survives", () => {
    expect(
      catalogBatchSchema.safeParse({ sources: [source({ fields: [{ name: "a b|c", count: 1 }] })] })
        .success,
    ).toBe(true);
  });
});

describe("lookups", () => {
  it("finds the sources a rule draws from", () => {
    expect(sourcesFor(catalog, "main", "WinEventLog:Security")).toHaveLength(1);
    expect(sourcesFor(catalog, "main", null)).toHaveLength(2);
    expect(sourcesFor(catalog, "other", null)).toHaveLength(0);
    expect(sourcesFor(catalog, "main", "Nope")).toHaveLength(0);
  });

  it("says how often a field appears", () => {
    const [security] = catalog.sources;
    expect(fieldPercent(security.fields[0], security)).toBe(100);
    expect(fieldPercent(security.fields[1], security)).toBe(25);
  });
});

describe("summarizeCatalog", () => {
  it("lists each source with its fields and a few example values", () => {
    const text = summarizeCatalog(catalog);
    expect(text).toContain(
      "- index=main sourcetype=WinEventLog:Security (200 events sampled over 24 h): EventCode [4625, 4624, 4672]; Source_Network_Address",
    );
    expect(text).toContain("index=main sourcetype=XmlWinEventLog:Sysmon");
    expect(text).not.toContain("4634");
  });

  it("puts a multi-line example value on one line", () => {
    const text = summarizeCatalog({
      sources: [
        {
          ...catalog.sources[0],
          fields: [
            {
              name: "Message",
              events_with_field: 1,
              distinct_values: 1,
              sample_values: [
                "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID: S-1-0-0",
              ],
            },
          ],
        },
      ],
    });
    expect(text).not.toMatch(/[\r\n\t]/);
    expect(text).toContain("Message [An account failed to log on. S]");
  });

  it("stays bounded however much is reported", () => {
    const huge: FieldCatalog = {
      sources: Array.from({ length: 20 }, (_, i) => ({
        index: `idx${i}`,
        sourcetype: "st",
        events_sampled: 10,
        window_hours: 24,
        reported_at: "2026-10-06T10:00:00Z",
        fields: Array.from({ length: 500 }, (_, j) => ({
          name: `field_${j}_${"x".repeat(60)}`,
          events_with_field: 1,
          distinct_values: 1,
          sample_values: ["y".repeat(200)],
        })),
      })),
    };
    const text = summarizeCatalog(huge);
    expect(text.length).toBeLessThanOrEqual(6000);
    expect(text.split("\n").length).toBeLessThanOrEqual(6);
  });
});

describe("ingestCatalog", () => {
  it("stores the report and audits who sent it and how much, never the example values", async () => {
    const store = vi.fn().mockResolvedValue({ sources: 1, fields: 1 });
    const audit = vi.fn().mockResolvedValue(true);
    const principal: ApiKeyPrincipal = {
      keyId: "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d",
      keyName: "Splunk lab",
      keyPrefix: "arc_KKKK",
      ownerId: "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69",
      scopes: ["ingest:splunk"],
    };
    const body = catalogBatchSchema.parse({
      sources: [source({ fields: [{ name: "user", count: 1, values: ["secret-account"] }] })],
    });
    const result = await ingestCatalog(
      principal,
      "splunk",
      body,
      { headers: new Headers() },
      {
        store,
        audit,
      },
    );
    expect(result).toEqual({ sources: 1, fields: 1 });
    expect(store).toHaveBeenCalledWith("splunk", body.sources);
    expect(audit).toHaveBeenCalledTimes(1);
    const entry = JSON.stringify(audit.mock.calls[0][0]);
    expect(entry).toContain('"action":"ingest.catalog"');
    expect(entry).toContain('"fields":1');
    expect(entry).not.toContain("secret-account");
  });
});
