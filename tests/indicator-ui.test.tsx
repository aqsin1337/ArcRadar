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
vi.mock("@/lib/indicators/repository", () => ({ findIndicators }));

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
    ({ supabase: {}, permissions: permissions ?? permissionsForRole(role) }) as never;

  beforeEach(() => vi.clearAllMocks());

  it("skips sources the caller may not read, without querying them", async () => {
    const result = await globalSearch(authFor("viewer", new Set()), "harbor", 6);
    expect(result).toEqual({ query: "harbor", groups: [] });
    expect(findIndicators).not.toHaveBeenCalled();
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
      },
    ]);
    expect(findIndicators.mock.calls[0][1]).toMatchObject({ q: "198.51", page: 1, page_size: 3 });
  });

  it("leaves out groups with no hits", async () => {
    findIndicators.mockResolvedValue({ total: 0, rows: [] });
    expect((await globalSearch(authFor("admin"), "nothing", 6)).groups).toEqual([]);
  });
});
