import { DEFAULT_PAGE_SIZE } from "@/lib/api/pagination";

/** The query string of a list page as an object: search text, filters, sorting and paging. */
export type ListState = Record<string, string | number | undefined>;

type Config = {
  /** The list page, for example `/alerts`. */
  path: string;
  /** Query-string keys that filter the list (`q` included). Changing one should reset to page 1. */
  filterKeys: readonly string[];
  defaultSort: string;
  defaultOrder?: "asc" | "desc";
};

const isSet = (value: string | number | undefined) => value !== undefined && value !== "";

/**
 * Builds the URL of a list page for a state with overrides applied. Defaults are left out so URLs stay
 * short and shareable. `hasActive` tells whether any search text or filter is set (sorting and paging
 * do not count).
 */
export function createListUrl({ path, filterKeys, defaultSort, defaultOrder = "desc" }: Config) {
  return {
    href(state: ListState, overrides: ListState = {}): string {
      const merged = { ...state, ...overrides };
      const params = new URLSearchParams();

      for (const key of filterKeys) {
        if (isSet(merged[key])) params.set(key, String(merged[key]));
      }
      const sort = String(merged.sort ?? defaultSort);
      const order = String(merged.order ?? defaultOrder);
      if (sort !== defaultSort || order !== defaultOrder) {
        params.set("sort", sort);
        params.set("order", order);
      }
      const page = Number(merged.page ?? 1);
      if (page > 1) params.set("page", String(page));
      const pageSize = Number(merged.page_size ?? DEFAULT_PAGE_SIZE);
      if (pageSize !== DEFAULT_PAGE_SIZE) params.set("page_size", String(pageSize));

      const query = params.toString();
      return query ? `${path}?${query}` : path;
    },
    hasActive(state: ListState): boolean {
      return filterKeys.some((key) => isSet(state[key]));
    },
  };
}
