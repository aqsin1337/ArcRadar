import { describe, expect, it } from "vitest";
import type { AuthClient } from "@/lib/auth/context";
import { ProviderError } from "@/lib/intel/types";
import {
  NvdProvider,
  mapNvdCve,
  nvdDate,
  parseCpe,
  severityFromScore,
} from "@/lib/vulnerabilities/nvd";
import { findSeverityStats, findVulnerabilities } from "@/lib/vulnerabilities/repository";
import {
  cveIdSchema,
  importVulnerabilitySchema,
  parseVulnerabilityListParams,
  vulnerabilityListQuerySchema,
} from "@/lib/vulnerabilities/schema";
import { hasActiveVulnerabilityFilters, vulnerabilityListHref } from "@/lib/vulnerabilities/url";

const NOW = new Date("2026-09-26T12:00:00.000Z");

// ---------------------------------------------------------------------------------------------
// Query and body schemas
// ---------------------------------------------------------------------------------------------

describe("vulnerabilityListQuerySchema", () => {
  const parse = (input: unknown) => vulnerabilityListQuerySchema.safeParse(input);

  it("defaults to the newest published first, page 1", () => {
    expect(parse({})).toMatchObject({
      success: true,
      data: { sort: "published_at", order: "desc", page: 1, page_size: 25 },
    });
  });

  it("reads filters and treats blank values as not set", () => {
    const result = parse({
      q: " log4j ",
      severity: "critical",
      exploit_status: "",
      min_cvss: "7.5",
      origin: "",
    });
    expect(result.success && result.data).toMatchObject({
      q: "log4j",
      severity: "critical",
      min_cvss: 7.5,
    });
    expect(result.success && result.data.exploit_status).toBeUndefined();
    expect(result.success && result.data.origin).toBeUndefined();
  });

  it("rejects unknown values instead of ignoring them", () => {
    expect(parse({ severity: "catastrophic" }).success).toBe(false);
    expect(parse({ exploit_status: "maybe" }).success).toBe(false);
    expect(parse({ sort: "description" }).success).toBe(false);
    expect(parse({ order: "sideways" }).success).toBe(false);
    expect(parse({ min_cvss: "11" }).success).toBe(false);
    expect(parse({ min_cvss: "-1" }).success).toBe(false);
    expect(parse({ q: "x".repeat(201) }).success).toBe(false);
    expect(parse({ page_size: "101" }).success).toBe(false);
  });

  it("falls back to the defaults for a hand-edited page URL, and says so", () => {
    expect(parseVulnerabilityListParams({ severity: "nope", q: "keep?" })).toMatchObject({
      ignoredInvalid: true,
      query: { sort: "published_at", page: 1 },
    });
    const fine = parseVulnerabilityListParams({ severity: ["high", "low"], sort: "cvss_score" });
    expect(fine).toMatchObject({
      ignoredInvalid: false,
      query: { severity: "high", sort: "cvss_score" },
    });
  });
});

describe("CVE ids", () => {
  it("are upper-cased and strictly validated", () => {
    expect(cveIdSchema.parse(" cve-2021-44228 ")).toBe("CVE-2021-44228");
    for (const bad of [
      "CVE-21-44228",
      "CVE-2021-1",
      "2021-44228",
      "CVE-2021-44228x",
      "",
      "CVE-2021-4422 8",
    ]) {
      expect(cveIdSchema.safeParse(bad).success, bad).toBe(false);
    }
  });

  it("are all an import body may carry", () => {
    expect(importVulnerabilitySchema.parse({ cve_id: "cve-2024-0001" })).toEqual({
      cve_id: "CVE-2024-0001",
    });
    for (const extra of [{ origin: "external" }, { severity: "low" }, { id: "1" }]) {
      expect(
        importVulnerabilitySchema.safeParse({ cve_id: "CVE-2024-0001", ...extra }).success,
      ).toBe(false);
    }
    expect(importVulnerabilitySchema.safeParse({}).success).toBe(false);
  });
});

describe("vulnerabilityListHref", () => {
  it("leaves defaults out and keeps filters, sorting and paging", () => {
    expect(vulnerabilityListHref({})).toBe("/vulnerabilities");
    expect(vulnerabilityListHref({ q: "log4j", severity: "critical", min_cvss: 9 })).toBe(
      "/vulnerabilities?q=log4j&severity=critical&min_cvss=9",
    );
    expect(vulnerabilityListHref({ sort: "cvss_score", order: "asc" }, { page: 3 })).toBe(
      "/vulnerabilities?sort=cvss_score&order=asc&page=3",
    );
    expect(
      vulnerabilityListHref({ sort: "published_at", order: "desc", page: 1, page_size: 25 }),
    ).toBe("/vulnerabilities");
    expect(vulnerabilityListHref({ q: "a b&c" })).toBe("/vulnerabilities?q=a+b%26c");
  });

  it("lets overrides win and clears a filter with an empty value", () => {
    expect(vulnerabilityListHref({ severity: "high", q: "x" }, { severity: "", page: 2 })).toBe(
      "/vulnerabilities?q=x&page=2",
    );
  });

  it("knows when a filter is active", () => {
    expect(hasActiveVulnerabilityFilters({})).toBe(false);
    expect(hasActiveVulnerabilityFilters({ sort: "cvss_score", page: 2 })).toBe(false);
    expect(hasActiveVulnerabilityFilters({ min_cvss: 0 })).toBe(true);
    expect(hasActiveVulnerabilityFilters({ exploit_status: "poc_available" })).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// NVD
// ---------------------------------------------------------------------------------------------

const LOG4J = {
  id: "CVE-2021-44228",
  published: "2021-12-10T10:15:09.143",
  lastModified: "2023-11-06T18:16:12.000",
  cisaExploitAdd: "2021-12-10",
  cisaRequiredAction: "Apply updates per vendor instructions.",
  cisaVulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
  descriptions: [
    { lang: "es", value: "Descripción en español." },
    {
      lang: "en",
      value:
        "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP. A second sentence.",
    },
  ],
  metrics: {
    cvssMetricV2: [
      {
        type: "Primary",
        baseSeverity: "HIGH",
        cvssData: { version: "2.0", vectorString: "AV:N/AC:M/Au:N/C:C/I:C/A:C", baseScore: 9.3 },
      },
    ],
    cvssMetricV31: [
      {
        type: "Secondary",
        cvssData: {
          version: "3.1",
          vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
          baseScore: 7.0,
          baseSeverity: "HIGH",
        },
      },
      {
        type: "Primary",
        cvssData: {
          version: "3.1",
          vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          baseScore: 10.0,
          baseSeverity: "CRITICAL",
        },
      },
    ],
  },
  configurations: [
    {
      nodes: [
        {
          cpeMatch: [
            {
              vulnerable: true,
              criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
              versionStartIncluding: "2.0.1",
              versionEndExcluding: "2.3.1",
            },
            { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:2.15.0:-:*:*:*:*:*:*" },
            {
              vulnerable: true,
              criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
              versionStartIncluding: "2.0.1",
              versionEndExcluding: "2.3.1",
            },
            { vulnerable: false, criteria: "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*" },
          ],
        },
      ],
    },
  ],
  references: [
    { url: "https://logging.apache.org/log4j/2.x/security.html", tags: ["Vendor Advisory"] },
    {
      url: "http://www.openwall.com/lists/oss-security/2021/12/10/1",
      tags: ["Exploit", "Mailing List"],
    },
    { url: "javascript:alert(1)" },
    { url: "https://logging.apache.org/log4j/2.x/security.html" },
  ],
};

const parseCve = (raw: object) =>
  new NvdProvider({
    apiKey: "k",
    fetchImpl: (async () =>
      new Response(JSON.stringify({ vulnerabilities: [{ cve: raw }] }))) as typeof fetch,
  }).lookupCve(String((raw as { id: string }).id).toUpperCase(), {
    signal: new AbortController().signal,
    now: NOW,
  });

describe("NVD mapping", () => {
  it("maps a fully described CVE", async () => {
    const record = await parseCve(LOG4J);
    expect(record).toMatchObject({
      cve_id: "CVE-2021-44228",
      title: "Apache Log4j2 Remote Code Execution Vulnerability",
      description: expect.stringMatching(/^Apache Log4j2 JNDI/),
      cvss_score: 10,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      cvss_version: "3.1",
      severity: "critical",
      exploit_status: "exploited_in_wild",
      remediation: "Apply updates per vendor instructions.",
      published_at: "2021-12-10T10:15:09.143Z",
      modified_at: "2023-11-06T18:16:12.000Z",
    });
    // Only http(s) references, without duplicates: a javascript: URL must never become a link.
    expect(record?.reference_urls).toEqual([
      "https://logging.apache.org/log4j/2.x/security.html",
      "http://www.openwall.com/lists/oss-security/2021/12/10/1",
    ]);
    // Non-vulnerable configuration entries are left out and duplicates collapse.
    expect(record?.affected_products).toEqual([
      {
        vendor: "apache",
        product: "log4j",
        affected_versions: ">= 2.0.1, < 2.3.1",
        fixed_version: "2.3.1",
      },
      { vendor: "apache", product: "log4j", affected_versions: "2.15.0", fixed_version: null },
    ]);
  });

  it("prefers the newest CVSS version and its primary score", () => {
    const withV4 = mapNvdCveFrom({
      metrics: {
        cvssMetricV31: [
          { type: "Primary", cvssData: { version: "3.1", baseScore: 5, baseSeverity: "MEDIUM" } },
        ],
        cvssMetricV40: [
          {
            type: "Primary",
            cvssData: {
              version: "4.0",
              baseScore: 9.3,
              baseSeverity: "CRITICAL",
              vectorString: "CVSS:4.0/AV:N",
            },
          },
        ],
      },
    });
    expect(withV4).toMatchObject({ cvss_version: "4.0", cvss_score: 9.3, severity: "critical" });

    const v2Only = mapNvdCveFrom({
      metrics: {
        cvssMetricV2: [
          { type: "Primary", baseSeverity: "HIGH", cvssData: { version: "2.0", baseScore: 10 } },
        ],
      },
    });
    expect(v2Only).toMatchObject({ cvss_version: "2.0", severity: "high" }); // never "critical" for v2
  });

  it("shows an unscored CVE as info with no score, not as a guess", () => {
    expect(mapNvdCveFrom({})).toMatchObject({
      cvss_score: null,
      cvss_vector: null,
      cvss_version: null,
      severity: "info",
      exploit_status: "unknown",
      remediation: null,
      published_at: null,
      affected_products: [],
    });
  });

  it("derives the exploit status only from evidence it has", () => {
    const refs = (tags: string[]) => ({ references: [{ url: "https://x.example/e", tags }] });
    expect(mapNvdCveFrom(refs(["Exploit"])).exploit_status).toBe("poc_available");
    expect(mapNvdCveFrom(refs(["Patch"])).exploit_status).toBe("unknown");
    expect(
      mapNvdCveFrom({ ...refs(["Exploit"]), cisaExploitAdd: "2024-01-01" }).exploit_status,
    ).toBe("exploited_in_wild");
  });

  it("titles a CVE by its CISA name, else by the first sentence, else by its id", () => {
    expect(
      mapNvdCveFrom({ descriptions: [{ lang: "en", value: "First sentence here. Second one." }] })
        .title,
    ).toBe("First sentence here.");
    expect(mapNvdCveFrom({}).title).toBe("CVE-2099-0001");
    expect(
      mapNvdCveFrom({ descriptions: [{ lang: "fr", value: "Seulement en français." }] })
        .description,
    ).toBe("Seulement en français.");
  });

  it("rates by the CVSS v3/v4 bands, and by NVD's own rating for v2", () => {
    const at = (score: number) => severityFromScore(score, "3.1");
    expect([10, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0].map(at)).toEqual([
      "critical",
      "critical",
      "high",
      "high",
      "medium",
      "medium",
      "low",
      "low",
      "info",
    ]);
    expect(severityFromScore(4.3, "4.0")).toBe("medium");
    expect(severityFromScore(9.3, "2.0", "HIGH")).toBe("high");
    expect(severityFromScore(5, "2.0", "MEDIUM")).toBe("medium");
    expect(severityFromScore(8, "2.0")).toBe("high");
    expect(severityFromScore(2, "2.0")).toBe("low");
  });

  it("reads CPE names, including escaped colons, and rejects the unusable", () => {
    expect(parseCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")).toEqual({
      vendor: "apache",
      product: "log4j",
      version: "2.14.1",
    });
    expect(parseCpe("cpe:2.3:a:ven\\:dor:prod:1.0:*:*:*:*:*:*:*")).toEqual({
      vendor: "ven:dor",
      product: "prod",
      version: "1.0",
    });
    expect(parseCpe("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")).toBeNull();
    expect(parseCpe("cpe:2.3:a:apache")).toBeNull();
    expect(parseCpe("not a cpe")).toBeNull();
  });

  it("reads NVD's zone-less timestamps as UTC", () => {
    expect(nvdDate("2021-12-10T10:15:09.143")).toBe("2021-12-10T10:15:09.143Z");
    expect(nvdDate("2021-12-10T10:15:09Z")).toBe("2021-12-10T10:15:09.000Z");
    expect(nvdDate("2021-12-10T10:15:09+01:00")).toBe("2021-12-10T09:15:09.000Z");
    expect(nvdDate("garbage")).toBeNull();
    expect(nvdDate(null)).toBeNull();
  });
});

function mapNvdCveFrom(fields: object) {
  return mapNvdCve({ id: "CVE-2099-0001", ...fields } as Parameters<typeof mapNvdCve>[0]);
}

describe("NvdProvider", () => {
  const context = { signal: new AbortController().signal, now: NOW };
  const provider = (respond: () => Response) => {
    const calls: { url: URL; init: RequestInit }[] = [];
    const impl = (async (input: URL, init?: RequestInit) => {
      calls.push({ url: input, init: init ?? {} });
      return respond();
    }) as unknown as typeof fetch;
    return { provider: new NvdProvider({ apiKey: "nvd-secret", fetchImpl: impl }), calls };
  };

  it("asks for one CVE with the key in a header", async () => {
    const { provider: nvd, calls } = provider(
      () => new Response(JSON.stringify({ vulnerabilities: [{ cve: LOG4J }] })),
    );
    const record = await nvd.lookupCve("CVE-2021-44228", context);

    expect(record?.cve_id).toBe("CVE-2021-44228");
    expect(calls[0].url.href).toBe(
      "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
    );
    expect(calls[0].init.headers).toMatchObject({ apiKey: "nvd-secret" });
    expect(calls[0].url.href).not.toContain("nvd-secret");
  });

  it("answers null for an unknown CVE, whether NVD says 404 or sends an empty list", async () => {
    expect(
      await provider(() => new Response("", { status: 404 })).provider.lookupCve(
        "CVE-2099-0001",
        context,
      ),
    ).toBeNull();
    expect(
      await provider(
        () => new Response(JSON.stringify({ vulnerabilities: [] })),
      ).provider.lookupCve("CVE-2099-0001", context),
    ).toBeNull();
    expect(
      await provider(
        () => new Response(JSON.stringify({ vulnerabilities: [{ cve: { id: "CVE-2099-0002" } }] })),
      ).provider.lookupCve("CVE-2099-0001", context),
    ).toBeNull();
  });

  it("tells a rejected key from an unknown CVE: NVD uses 404 for both", async () => {
    const rejected = provider(
      () => new Response("", { status: 404, headers: { message: "Invalid apiKey." } }),
    );
    await expect(rejected.provider.lookupCve("CVE-2021-44228", context)).rejects.toMatchObject({
      reason: "auth",
    });

    const unknown = provider(
      () => new Response("", { status: 404, headers: { message: "Invalid cveId." } }),
    );
    expect(await unknown.provider.lookupCve("CVE-2099-0001", context)).toBeNull();
  });

  it("does not trust a malformed answer, and reports provider failures", async () => {
    const wrong = provider(
      () => new Response(JSON.stringify({ vulnerabilities: [{ cve: { id: 5 } }] })),
    );
    await expect(wrong.provider.lookupCve("CVE-2099-0001", context)).rejects.toMatchObject({
      reason: "bad_response",
    });

    const limited = provider(() => new Response("", { status: 403 }));
    const error = await limited.provider
      .lookupCve("CVE-2099-0001", context)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ProviderError);
    expect((error as Error).message).not.toContain("nvd-secret");
  });
});

// ---------------------------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------------------------

/** A chainable, awaitable stand-in for a Supabase query that records what was asked. */
function fakeSupabase(results: unknown[]) {
  const calls: [string, unknown[]][] = [];
  const builder: unknown = new Proxy(
    {},
    {
      get(_target, property) {
        if (property === "then") {
          return (resolve: (value: unknown) => void) => resolve(results.shift());
        }
        return (...args: unknown[]) => {
          calls.push([String(property), args]);
          return builder;
        };
      },
    },
  );
  const client = {
    rpc: (...args: unknown[]) => {
      calls.push(["rpc", args]);
      return builder;
    },
  } as unknown as AuthClient;
  return { client, calls };
}

const base = { page: 1, page_size: 25, sort: "published_at", order: "desc" } as const;

describe("findVulnerabilities", () => {
  it("searches through the SQL function and filters, sorts (empty values last) and pages in PostgREST", async () => {
    const { client, calls } = fakeSupabase([{ data: [{ id: "1" }], error: null, count: 40 }]);
    const result = await findVulnerabilities(client, {
      ...base,
      q: "log4j",
      severity: "critical",
      exploit_status: "exploited_in_wild",
      origin: "demo",
      min_cvss: 7.5,
      sort: "cvss_score",
      order: "desc",
      page: 2,
    });

    expect(result).toEqual({ rows: [{ id: "1" }], total: 40 });
    expect(calls).toEqual([
      ["rpc", ["search_vulnerabilities", { p_query: "log4j" }, { count: "exact" }]],
      ["eq", ["severity", "critical"]],
      ["eq", ["exploit_status", "exploited_in_wild"]],
      ["eq", ["origin", "demo"]],
      ["gte", ["cvss_score", 7.5]],
      ["order", ["cvss_score", { ascending: false, nullsFirst: false }]],
      ["order", ["id", { ascending: true }]],
      ["range", [25, 49]],
    ]);
  });

  it("returns an empty page with the real total when the page is past the last one", async () => {
    const { client, calls } = fakeSupabase([
      {
        data: null,
        error: { code: "PGRST103", message: "Requested range not satisfiable" },
        count: null,
      },
      { data: [{ id: "1" }], error: null, count: 40 },
    ]);
    const result = await findVulnerabilities(client, { ...base, page: 99 });
    expect(result).toEqual({ rows: [], total: 40 });
    expect(calls.filter(([name]) => name === "range").map(([, args]) => args)).toEqual([
      [2450, 2474],
      [0, 0],
    ]);
  });

  it("turns database errors into safe API errors", async () => {
    const { client } = fakeSupabase([
      { data: null, error: { code: "XX000", message: "secret detail" }, count: null },
    ]);
    await expect(findVulnerabilities(client, base)).rejects.toMatchObject({ status: 500 });
  });
});

describe("findSeverityStats", () => {
  it("lists every severity, most severe first, with zeros filled in", async () => {
    const { client, calls } = fakeSupabase([
      {
        data: [
          { severity: "low", total: 1, exploited: 0 },
          { severity: "critical", total: 5, exploited: 3 },
          { severity: "medium", total: "2", exploited: "1" },
        ],
        error: null,
      },
    ]);
    const stats = await findSeverityStats(client);

    expect(calls).toEqual([["rpc", ["vulnerability_severity_counts"]]]);
    expect(stats.by_severity.map((row) => row.severity)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ]);
    expect(stats.by_severity).toEqual([
      { severity: "critical", total: 5, exploited: 3 },
      { severity: "high", total: 0, exploited: 0 },
      { severity: "medium", total: 2, exploited: 1 },
      { severity: "low", total: 1, exploited: 0 },
      { severity: "info", total: 0, exploited: 0 },
    ]);
    expect(stats).toMatchObject({ total: 8, exploited: 4 });
  });

  it("is all zeros when the caller can see nothing", async () => {
    const { client } = fakeSupabase([{ data: [], error: null }]);
    expect(await findSeverityStats(client)).toMatchObject({ total: 0, exploited: 0 });
  });
});
