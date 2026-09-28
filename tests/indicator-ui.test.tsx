import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TagChips } from "@/components/indicators/tag-chips";
import { IndicatorStatusBadge } from "@/components/ui/domain-badges";
import { Pagination, pageWindow } from "@/components/ui/pagination";
import { SelectField } from "@/components/ui/select";
import { TagInput } from "@/components/ui/tag-input";
import { TextAreaField } from "@/components/ui/textarea";
import { formatDate, formatDateTime, toDateTimeLocalValue } from "@/lib/format";
import { hasActiveFilters, indicatorListHref } from "@/lib/indicators/url";
import { globalSearch } from "@/lib/search/service";
import { permissionsForRole } from "@/lib/rbac/permissions";

const findIndicators = vi.hoisted(() => vi.fn());
const findVulnerabilities = vi.hoisted(() => vi.fn());
const findAlerts = vi.hoisted(() => vi.fn());
const findInvestigations = vi.hoisted(() => vi.fn());
const findActors = vi.hoisted(() => vi.fn());
const findCampaigns = vi.hoisted(() => vi.fn());
const findMalwareFamilies = vi.hoisted(() => vi.fn());
const findTechniques = vi.hoisted(() => vi.fn());
vi.mock("@/lib/indicators/repository", () => ({ findIndicators }));
vi.mock("@/lib/vulnerabilities/repository", () => ({ findVulnerabilities }));
vi.mock("@/lib/alerts/repository", () => ({ findAlerts }));
vi.mock("@/lib/investigations/repository", () => ({ findInvestigations }));
vi.mock("@/lib/threat-intel/repository", () => ({
  findActors,
  findCampaigns,
  findMalwareFamilies,
  findTechniques,
}));

const html = (node: React.ReactElement) => renderToStaticMarkup(node);

describe("pageWindow", () => {
  it("shows every page when there are few, and elides the middle of long lists", () => {
    expect(pageWindow(1, 1)).toEqual([1]);
    expect(pageWindow(1, 2)).toEqual([1, 2]);
    expect(pageWindow(2, 3)).toEqual([1, 2, 3]);
    expect(pageWindow(5, 10)).toEqual([1, "gap", 4, 5, 6, "gap", 10]);
    expect(pageWindow(2, 10)).toEqual([1, 2, 3, "gap", 10]);
    expect(pageWindow(10, 10)).toEqual([1, "gap", 9, 10]);
  });
});

describe("indicatorListHref", () => {
  it("leaves out defaults so addresses stay short", () => {
    expect(indicatorListHref({})).toBe("/indicators");
    expect(
      indicatorListHref({ sort: "last_seen", order: "desc", page: 1, page_size: 25, q: "" }),
    ).toBe("/indicators");
  });

  it("encodes text and keeps filters, sort and paging", () => {
    const href = indicatorListHref({
      q: "login & pay",
      type: "domain",
      verdict: "malicious",
      tag: "c2",
      sort: "confidence",
      order: "asc",
      page: 3,
      page_size: 50,
    });
    const params = new URL(href, "http://x").searchParams;
    expect(href.startsWith("/indicators?")).toBe(true);
    expect(params.get("q")).toBe("login & pay");
    expect(Object.fromEntries(params)).toMatchObject({
      type: "domain",
      verdict: "malicious",
      tag: "c2",
      sort: "confidence",
      order: "asc",
      page: "3",
      page_size: "50",
    });
  });

  it("applies overrides on top of the current state, and empty strings clear a filter", () => {
    const base = { q: "a", type: "domain", page: 4 };
    expect(indicatorListHref(base, { page: 1 })).toBe("/indicators?q=a&type=domain");
    expect(indicatorListHref(base, { type: "", page: 1 })).toBe("/indicators?q=a");
    expect(indicatorListHref(base, { sort: "severity", order: "desc", page: 1 })).toContain(
      "sort=severity&order=desc",
    );
  });

  it("only writes a non-default order together with its sort field", () => {
    expect(indicatorListHref({ order: "asc" })).toBe("/indicators?sort=last_seen&order=asc");
  });

  it("knows when a search or filter is active (sorting and paging do not count)", () => {
    expect(hasActiveFilters({})).toBe(false);
    expect(hasActiveFilters({ sort: "value", page: 2, q: "" })).toBe(false);
    expect(hasActiveFilters({ tag: "c2" })).toBe(true);
    expect(hasActiveFilters({ q: "x" })).toBe(true);
  });
});

describe("date formatting", () => {
  it("formats in UTC so server and browser agree", () => {
    expect(formatDate("2026-09-26T23:30:00Z")).toBe("26 Sept 2026");
    expect(formatDateTime("2026-09-26T09:05:00Z")).toBe("26 Sept 2026, 09:05 UTC");
  });

  it("produces the value shape datetime-local inputs need", () => {
    expect(toDateTimeLocalValue("2026-09-26T09:05:59Z")).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
  });
});

describe("Pagination", () => {
  const props = {
    pageSize: 25,
    noun: "indicators",
    hrefForPage: (page: number) => `/x?page=${page}`,
  };

  it("says where you are and marks the current page", () => {
    const markup = html(<Pagination {...props} page={2} totalPages={2} total={41} />);
    expect(markup).toContain("Showing 26–41 of 41 indicators");
    expect(markup).toContain('aria-current="page"');
    expect(markup).toContain('aria-label="Page 1"');
    expect(markup).toContain('href="/x?page=1"');
  });

  it("disables previous on the first page and next on the last", () => {
    const first = html(<Pagination {...props} page={1} totalPages={2} total={41} />);
    expect(first).toMatch(
      /aria-disabled="true"[^>]*aria-label="Previous page"|aria-label="Previous page"[^>]*aria-disabled="true"/,
    );
    const last = html(<Pagination {...props} page={2} totalPages={2} total={41} />);
    expect(last).toMatch(
      /aria-label="Next page"[^>]*aria-disabled="true"|aria-disabled="true"[^>]*aria-label="Next page"/,
    );
  });

  it("renders nothing for an empty list and no page links for a single page", () => {
    expect(html(<Pagination {...props} page={1} totalPages={0} total={0} />)).toBe("");
    const single = html(<Pagination {...props} page={1} totalPages={1} total={3} />);
    expect(single).toContain("Showing 1–3 of 3 indicators");
    expect(single).not.toContain("Next page");
  });
});

describe("TagChips", () => {
  const tags = [
    { id: "1", name: "c2", color: "#ef4444" },
    { id: "2", name: "phishing", color: null },
    { id: "3", name: "apt", color: "#8b5cf6" },
    { id: "4", name: "internal", color: null },
  ];

  it("shows a dash when there are no tags", () => {
    expect(html(<TagChips tags={[]} />)).toContain("—");
  });

  it("limits the visible tags and says how many are hidden", () => {
    const markup = html(<TagChips tags={tags} limit={2} />);
    expect(markup).toContain("c2");
    expect(markup).toContain("phishing");
    expect(markup).not.toContain(">apt<");
    expect(markup).toContain("+2");
    expect(markup).toContain('title="apt, internal"');
  });

  it("uses the stored color only as a decorative dot, never for the text", () => {
    const markup = html(<TagChips tags={tags} />);
    expect(markup).toContain("background-color:#ef4444");
    expect(markup).not.toMatch(/color:#ef4444[^"]*"[^>]*>c2/);
  });
});

describe("TagInput", () => {
  it("renders the current tags with individually labelled remove buttons and a counter", () => {
    const markup = html(
      <TagInput
        id="tags"
        label="Tags"
        value={["c2", "phishing"]}
        onChange={() => {}}
        suggestions={["c2", "apt"]}
      />,
    );
    expect(markup).toContain('aria-label="Remove tag c2"');
    expect(markup).toContain('aria-label="Remove tag phishing"');
    expect(markup).toContain("2 of 20 used.");
    expect(markup).toContain('for="tags"');
    // Only tags that are not already chosen are suggested.
    expect(markup).toContain('<option value="apt">');
    expect(markup).not.toContain('<option value="c2">');
  });

  it("shows a server-side error on the field", () => {
    const markup = html(
      <TagInput id="tags" label="Tags" value={[]} onChange={() => {}} error="Too many tags." />,
    );
    expect(markup).toContain("Too many tags.");
    expect(markup).toContain('role="alert"');
  });
});

describe("form fields", () => {
  it("SelectField renders its options, an optional placeholder and the label", () => {
    const markup = html(
      <SelectField
        id="type"
        label="Type"
        placeholder="Any"
        options={[{ value: "a", label: "Alpha" }]}
      />,
    );
    expect(markup).toContain('for="type"');
    expect(markup).toContain('<option value="">Any</option>');
    expect(markup).toContain('<option value="a">Alpha</option>');
  });

  it("TextAreaField wires its error for assistive tech", () => {
    const markup = html(<TextAreaField id="d" label="Description" error="Too long." />);
    expect(markup).toContain('aria-invalid="true"');
    expect(markup).toContain('aria-describedby="d-error"');
  });
});

describe("IndicatorStatusBadge", () => {
  it("labels each status in words", () => {
    expect(html(<IndicatorStatusBadge status="under_review" />)).toContain("Under review");
    expect(html(<IndicatorStatusBadge status="whitelisted" />)).toContain("Allow-listed");
  });
});

describe("globalSearch", () => {
  const authFor = (role: "viewer" | "admin", permissions?: Set<string>) =>
    ({
      supabase: {},
      user: { id: "user-1" },
      permissions: permissions ?? permissionsForRole(role),
    }) as never;

  const sources = [
    findIndicators,
    findVulnerabilities,
    findAlerts,
    findInvestigations,
    findActors,
    findCampaigns,
    findMalwareFamilies,
    findTechniques,
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    for (const source of sources) source.mockResolvedValue({ total: 0, rows: [] });
  });

  it("skips sources the caller may not read, without querying them", async () => {
    const result = await globalSearch(authFor("viewer", new Set()), "harbor", 6);
    expect(result).toEqual({ query: "harbor", groups: [] });
    for (const source of sources) expect(source).not.toHaveBeenCalled();
  });

  it("searches alerts and investigations as the caller, and only with their permissions", async () => {
    await globalSearch(authFor("viewer", new Set(["alerts:read"])), "beacon", 4);
    expect(findAlerts).toHaveBeenCalledOnce();
    expect(findAlerts.mock.calls[0][1]).toMatchObject({ q: "beacon", page: 1, page_size: 4 });
    expect(findAlerts.mock.calls[0][2]).toBe("user-1");
    expect(findInvestigations).not.toHaveBeenCalled();
    expect(findActors).not.toHaveBeenCalled();
  });

  it("one threat_intel:read permission opens actors, campaigns, malware and techniques", async () => {
    await globalSearch(authFor("viewer", new Set(["threat_intel:read"])), "harbor", 5);
    for (const source of [findActors, findCampaigns, findMalwareFamilies, findTechniques]) {
      expect(source).toHaveBeenCalledOnce();
      expect(source.mock.calls[0][1]).toMatchObject({ q: "harbor", page: 1, page_size: 5 });
    }
    expect(findAlerts).not.toHaveBeenCalled();
  });

  it("links alerts, investigations and threat intelligence to their pages with provenance", async () => {
    findAlerts.mockResolvedValue({
      total: 1,
      rows: [
        {
          id: "a-1",
          title: "Beacon to 203.0.113.9",
          severity: "high",
          status: "new",
          source: "wazuh",
          origin: "demo",
        },
      ],
    });
    findInvestigations.mockResolvedValue({
      total: 1,
      rows: [
        { id: "i-1", title: "Harbor Lights", status: "open", priority: "high", origin: "local" },
      ],
    });
    findActors.mockResolvedValue({
      total: 1,
      rows: [
        {
          id: "t-1",
          name: "Crimson Harbor",
          motivation: "Financial gain",
          aliases: ["DEMO-FIN-01"],
          origin: "demo",
        },
      ],
    });
    findCampaigns.mockResolvedValue({
      total: 1,
      rows: [{ id: "c-1", name: "Harbor Lights", status: "active", origin: "demo" }],
    });
    findMalwareFamilies.mockResolvedValue({
      total: 1,
      rows: [
        {
          id: "m-1",
          name: "NightLoader",
          malware_type: "Loader",
          platforms: ["Windows"],
          origin: "demo",
        },
      ],
    });
    findTechniques.mockResolvedValue({
      total: 1,
      rows: [{ id: "T1566", name: "Phishing", tactics: ["Initial Access"] }],
    });

    const { groups } = await globalSearch(authFor("viewer"), "harbor", 6);
    const hits = Object.fromEntries(groups.map((group) => [group.kind, group.hits[0]]));

    expect(hits.alert).toEqual({
      id: "a-1",
      title: "Beacon to 203.0.113.9",
      subtitle: "High · New · wazuh",
      href: "/alerts/a-1",
      origin: "demo",
    });
    expect(hits.investigation).toEqual({
      id: "i-1",
      title: "Harbor Lights",
      subtitle: "Open · High",
      href: "/investigations/i-1",
      origin: "local",
    });
    expect(hits.threat_actor).toEqual({
      id: "t-1",
      title: "Crimson Harbor",
      subtitle: "Financial gain · aka DEMO-FIN-01",
      href: "/threat-actors/t-1",
      origin: "demo",
    });
    expect(hits.campaign).toEqual({
      id: "c-1",
      title: "Harbor Lights",
      subtitle: "Campaign · Active",
      href: "/campaigns/c-1",
      origin: "demo",
    });
    expect(hits.malware).toEqual({
      id: "m-1",
      title: "NightLoader",
      subtitle: "Loader · Windows",
      href: "/malware/m-1",
      origin: "demo",
    });
    // ATT&CK techniques are reference data with no origin of their own.
    expect(hits.technique).toEqual({
      id: "T1566",
      title: "T1566 Phishing",
      subtitle: "Initial Access",
      href: "/mitre/T1566",
      origin: null,
      mono: true,
    });
  });

  it("searches only the sources a permission opens", async () => {
    await globalSearch(authFor("viewer", new Set(["vulnerabilities:read"])), "log4j", 4);
    expect(findIndicators).not.toHaveBeenCalled();
    expect(findVulnerabilities).toHaveBeenCalledOnce();
    expect(findVulnerabilities.mock.calls[0][1]).toMatchObject({
      q: "log4j",
      page: 1,
      page_size: 4,
    });
  });

  it("returns vulnerability hits with a CVE link, severity, score and provenance", async () => {
    findVulnerabilities.mockResolvedValue({
      total: 2,
      rows: [
        {
          id: "v-1",
          cve_id: "CVE-2021-44228",
          title: "Apache Log4j2 JNDI remote code execution",
          severity: "critical",
          cvss_score: 10,
          origin: "demo",
        },
        {
          id: "v-2",
          cve_id: "CVE-2099-0001",
          title: "Unscored",
          severity: "info",
          cvss_score: null,
          origin: "external",
        },
      ],
    });
    const result = await globalSearch(authFor("viewer"), "log4j", 6);

    expect(result.groups).toHaveLength(1);
    expect(result.groups[0]).toMatchObject({
      kind: "vulnerability",
      label: "Vulnerabilities",
      total: 2,
    });
    expect(result.groups[0].hits).toEqual([
      {
        id: "v-1",
        title: "CVE-2021-44228",
        subtitle: "Critical · CVSS 10.0 · Apache Log4j2 JNDI remote code execution",
        href: "/vulnerabilities/CVE-2021-44228",
        origin: "demo",
        mono: true,
      },
      {
        id: "v-2",
        title: "CVE-2099-0001",
        subtitle: "Info · Not scored · Unscored",
        href: "/vulnerabilities/CVE-2099-0001",
        origin: "external",
        mono: true,
      },
    ]);
  });

  it.each([
    ["198.51.100.23", "ip", "/intelligence/ip?q=198.51.100.23", "IP intelligence"],
    [
      "Login-Secure.EXAMPLE",
      "domain",
      "/intelligence/domain?q=login-secure.example",
      "Domain intelligence",
    ],
    [
      "https://login.example/a?b=c",
      "url",
      "/intelligence/url?q=https%3A%2F%2Flogin.example%2Fa%3Fb%3Dc",
      "URL analysis",
    ],
    [
      "D41D8CD98F00B204E9800998ECF8427E",
      "hash",
      "/intelligence/hash?q=d41d8cd98f00b204e9800998ecf8427e",
      "Hash lookup",
    ],
  ])(
    "offers to look %s up, first in the list, without claiming anything about it",
    async (query, kind, href, page) => {
      const result = await globalSearch(authFor("viewer"), query, 6);

      expect(result.groups).toHaveLength(1);
      expect(result.groups[0]).toMatchObject({ kind: "lookup", label: "Look up", total: 1 });
      expect(result.groups[0].hits[0]).toMatchObject({ id: `lookup:${kind}`, href, origin: null });
      expect(result.groups[0].hits[0].subtitle).toContain(page);
      expect(result.groups[0].hits[0].subtitle).not.toMatch(/malicious|suspicious|safe/i);
    },
  );

  it("puts the lookup offer before the record hits", async () => {
    findIndicators.mockResolvedValue({
      total: 1,
      rows: [
        {
          id: "id-1",
          type: "ipv4",
          value: "198.51.100.23",
          verdict: "malicious",
          severity: "critical",
          origin: "demo",
        },
      ],
    });
    const result = await globalSearch(authFor("viewer"), "198.51.100.23", 6);
    expect(result.groups.map((group) => group.kind)).toEqual(["lookup", "indicator"]);
  });

  it("offers no lookup for plain words, CVE ids or callers who cannot read indicators", async () => {
    expect((await globalSearch(authFor("viewer"), "harbor", 6)).groups).toEqual([]);
    expect((await globalSearch(authFor("viewer"), "CVE-2021-44228", 6)).groups).toEqual([]);
    expect(
      (await globalSearch(authFor("viewer", new Set(["vulnerabilities:read"])), "198.51.100.23", 6))
        .groups,
    ).toEqual([]);
  });

  it("returns grouped hits with a link, a readable subtitle and the provenance", async () => {
    findIndicators.mockResolvedValue({
      total: 9,
      rows: [
        {
          id: "id-1",
          type: "ipv4",
          value: "198.51.100.23",
          verdict: "malicious",
          severity: "critical",
          origin: "demo",
        },
      ],
    });
    const result = await globalSearch(authFor("viewer"), "198.51", 3);

    expect(result.groups).toHaveLength(1);
    expect(result.groups[0]).toMatchObject({ kind: "indicator", label: "Indicators", total: 9 });
    expect(result.groups[0].hits).toEqual([
      {
        id: "id-1",
        title: "198.51.100.23",
        subtitle: "IPv4 · Malicious · Critical",
        href: "/indicators/id-1",
        origin: "demo",
        mono: true,
      },
    ]);
    expect(findIndicators.mock.calls[0][1]).toMatchObject({ q: "198.51", page: 1, page_size: 3 });
  });

  it("leaves out groups with no hits", async () => {
    findIndicators.mockResolvedValue({ total: 0, rows: [] });
    expect((await globalSearch(authFor("admin"), "nothing", 6)).groups).toEqual([]);
  });
});
