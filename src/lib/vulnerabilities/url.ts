import { DEFAULT_PAGE_SIZE } from "@/lib/api/pagination";

export type VulnerabilityListState = {
  q?: string;
  severity?: string;
  exploit_status?: string;
  origin?: string;
  min_cvss?: string | number;
  sort?: string;
  order?: string;
  page?: number;
  page_size?: number;
};

const FILTER_KEYS = ["q", "severity", "exploit_status", "origin", "min_cvss"] as const;

/** Whether any search text or filter is set (sorting and paging do not count). */
export function hasActiveVulnerabilityFilters(state: VulnerabilityListState): boolean {
  return FILTER_KEYS.some((key) => state[key] !== undefined && state[key] !== "");
}

/**
 * URL of the vulnerability list for `state` with `overrides` applied. Defaults are left out so URLs
 * stay short and shareable. Change a filter or the sort and you should pass `page: 1`.
 */
export function vulnerabilityListHref(
  state: VulnerabilityListState,
  overrides: VulnerabilityListState = {},
): string {
  const merged = { ...state, ...overrides };
  const params = new URLSearchParams();

  for (const key of FILTER_KEYS) {
    const value = merged[key];
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  if ((merged.sort ?? "published_at") !== "published_at" || (merged.order ?? "desc") !== "desc") {
    params.set("sort", merged.sort ?? "published_at");
    params.set("order", merged.order ?? "desc");
  }
  if (merged.page && merged.page > 1) params.set("page", String(merged.page));
  if (merged.page_size && merged.page_size !== DEFAULT_PAGE_SIZE) {
    params.set("page_size", String(merged.page_size));
  }

  const query = params.toString();
  return query ? `/vulnerabilities?${query}` : "/vulnerabilities";
}
