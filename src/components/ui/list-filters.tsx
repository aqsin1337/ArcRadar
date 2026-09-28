"use client";

import { Search, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/cn";

export type FilterField = {
  /** The query-string key, for example `severity`. */
  key: string;
  label: string;
  /** Text of the "no filter" option, for example "Any severity". */
  all: string;
  options: readonly { value: string; label: string }[];
};

type ListState = Record<string, string | number | undefined>;

type Props = {
  ariaLabel: string;
  searchId: string;
  searchLabel: string;
  searchPlaceholder: string;
  /** The current query string as an object: search text, filters, sorting. */
  state: ListState;
  fields: readonly FilterField[];
  sort: {
    fields: readonly { value: string; label: string }[];
    defaultField: string;
  };
  /** URL of the list for a state with overrides applied (see `indicatorListHref`). */
  hrefFor: (state: ListState, overrides: ListState) => string;
  /** Tailwind grid classes for the filter menus. */
  gridClassName?: string;
  /** Show the search box (default). A list with nothing to search by text leaves it out. */
  showSearch?: boolean;
};

const SEARCH_DELAY_MS = 350;

const text = (value: string | number | undefined) => (value === undefined ? "" : String(value));

/**
 * Search box, filter menus and sort menu for a list page. The URL is the source of truth (shareable,
 * back-button friendly): every change rewrites the query string and resets to page 1, and the page
 * re-renders on the server. Typing is debounced; Enter searches at once.
 */
export function ListFilters({
  ariaLabel,
  searchId,
  searchLabel,
  searchPlaceholder,
  state,
  fields,
  sort,
  hrefFor,
  gridClassName = "grid-cols-2 sm:grid-cols-3 lg:grid-cols-6",
  showSearch = true,
}: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [query, setQuery] = useState(text(state.q));
  const [filters, setFilters] = useState<Record<string, string>>(() => pick(fields, state));
  const [searchFocused, setSearchFocused] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Follow the URL when it changes from outside (back button, a link), but never overwrite text the
  // user is typing right now. This is React's "adjust state while rendering" pattern, guarded by a key.
  const urlKey = JSON.stringify(state);
  const [syncedKey, setSyncedKey] = useState(urlKey);
  if (syncedKey !== urlKey) {
    setSyncedKey(urlKey);
    setFilters(pick(fields, state));
    if (!searchFocused) setQuery(text(state.q));
  }

  useEffect(() => () => clearTimeout(timer.current), []);

  function go(next: ListState) {
    clearTimeout(timer.current);
    startTransition(() => router.replace(hrefFor(state, { ...next, page: 1 })));
  }

  function onSearchChange(value: string) {
    setQuery(value);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => go({ ...filters, q: value.trim() }), SEARCH_DELAY_MS);
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    go({ ...filters, q: query.trim() });
  }

  function onSelect(key: string, value: string) {
    setFilters((current) => ({ ...current, [key]: value }));
    go({ ...filters, [key]: value, q: query.trim() });
  }

  function onSort(field: string, order: string) {
    go({ ...filters, q: query.trim(), sort: field, order });
  }

  function clear() {
    setQuery("");
    setFilters(pick(fields, {}));
    go({ q: "", ...Object.fromEntries(fields.map((field) => [field.key, ""])) });
    input.current?.focus();
  }

  const active = query !== "" || fields.some((field) => filters[field.key] !== "");

  return (
    <form role="search" aria-label={ariaLabel} onSubmit={onSubmit} className="space-y-3">
      <div className={cn("relative", !showSearch && "hidden")}>
        <label htmlFor={searchId} className="sr-only">
          {searchLabel}
        </label>
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"
        />
        <input
          ref={input}
          id={searchId}
          type="search"
          value={query}
          onChange={(event) => onSearchChange(event.target.value)}
          onFocus={() => setSearchFocused(true)}
          onBlur={() => setSearchFocused(false)}
          placeholder={searchPlaceholder}
          autoComplete="off"
          maxLength={200}
          className="h-10 w-full rounded-lg border border-input-border bg-surface pr-10 pl-9 text-sm text-foreground placeholder:text-muted focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0"
        />
        <span className="absolute top-1/2 right-3 -translate-y-1/2" role="status">
          {pending ? (
            <>
              <Spinner className="text-muted" />
              <span className="sr-only">Updating results</span>
            </>
          ) : null}
        </span>
      </div>

      <div className={cn("grid gap-2", gridClassName)}>
        {fields.map((field) => (
          <label key={field.key} className="block space-y-1">
            <span className="text-xs font-medium text-muted">{field.label}</span>
            <Select
              value={filters[field.key] ?? ""}
              onChange={(event) => onSelect(field.key, event.target.value)}
              className="h-9"
            >
              <option value="">{field.all}</option>
              {field.options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </label>
        ))}
      </div>

      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <div className="min-h-8">
          {active && (
            <Button type="button" variant="ghost" size="sm" onClick={clear}>
              <X aria-hidden className="size-4" />
              Clear search and filters
            </Button>
          )}
        </div>
        <div className="flex items-end gap-2">
          <label className="block space-y-1">
            <span className="text-xs font-medium text-muted">Sort by</span>
            <Select
              value={text(state.sort) || sort.defaultField}
              onChange={(event) => onSort(event.target.value, text(state.order) || "desc")}
              className="h-9 w-40"
            >
              {sort.fields.map((field) => (
                <option key={field.value} value={field.value}>
                  {field.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-1">
            <span className="sr-only">Order</span>
            <Select
              value={text(state.order) || "desc"}
              onChange={(event) =>
                onSort(text(state.sort) || sort.defaultField, event.target.value)
              }
              className="h-9 w-36"
              aria-label="Sort order"
            >
              <option value="desc">Descending</option>
              <option value="asc">Ascending</option>
            </Select>
          </label>
        </div>
      </div>
    </form>
  );
}

function pick(fields: readonly FilterField[], state: ListState): Record<string, string> {
  return Object.fromEntries(fields.map((field) => [field.key, text(state[field.key])]));
}
