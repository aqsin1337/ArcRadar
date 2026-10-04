import { DEFAULT_PAGE_SIZE } from "@/lib/api/pagination";

export type ListState = {
  q?: string;
  type?: string;
  status?: string;
  verdict?: string;
  severity?: string;
  origin?: string;
  tag?: string;
  sort?: string;
  order?: string;
  page?: number;
  page_size?: number;
};

const FILTER_KEYS = ["q", "type", "status", "verdict", "severity", "origin", "tag"] as const;

/** Whether any search text or filter is set (sorting and paging do not count). */
export function hasActiveFilters(state: ListState): boolean {
  return FILTER_KEYS.some((key) => Boolean(state[key]));
}

/**
 * URL of the indicator list for `state` with `overrides` applied. Defaults are left out so URLs stay
 * short and shareable. Change a filter or the sort and you should pass `page: 1`.
 */
export function indicatorListHref(state: ListState, overrides: ListState = {}): string {
  const merged = { ...state, ...overrides };
  const params = new URLSearchParams();

  for (const key of FILTER_KEYS) {
    const value = merged[key];
    if (value) params.set(key, value);
  }
  if ((merged.sort ?? "last_seen") !== "last_seen" || (merged.order ?? "desc") !== "desc") {
    params.set("sort", merged.sort ?? "last_seen");
    params.set("order", merged.order ?? "desc");
  }
  if (merged.page && merged.page > 1) params.set("page", String(merged.page));
  if (merged.page_size && merged.page_size !== DEFAULT_PAGE_SIZE) {
    params.set("page_size", String(merged.page_size));
  }

  const query = params.toString();
  return query ? `/indicators?${query}` : "/indicators";
}
