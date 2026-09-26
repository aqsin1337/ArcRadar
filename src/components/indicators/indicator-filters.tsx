"use client";

import { Search, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition, type FormEvent, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import {
  DATA_ORIGINS,
  INDICATOR_STATUSES,
  INDICATOR_STATUS_LABELS,
  INDICATOR_TYPES,
  INDICATOR_SORT_FIELDS,
  INDICATOR_TYPE_LABELS,
  ORIGIN_LABELS,
  SORT_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
  VERDICTS,
  VERDICT_LABELS,
} from "@/lib/indicators/constants";
import { hasActiveFilters, indicatorListHref, type ListState } from "@/lib/indicators/url";

type FilterKey = "type" | "status" | "verdict" | "severity" | "origin" | "tag";

const SEARCH_DELAY_MS = 350;

/**
 * Search box and filter menus for the indicator list. The URL is the source of truth (shareable,
 * back-button friendly): every change rewrites the query string and resets to page 1, and the page
 * re-renders on the server. Typing is debounced; Enter searches at once.
 */
export function IndicatorFilters({ state, tags }: { state: ListState; tags: string[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [text, setText] = useState(state.q ?? "");
  const [filters, setFilters] = useState<Record<FilterKey, string>>(() => pick(state));
  const [searchFocused, setSearchFocused] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Follow the URL when it changes from outside (back button, a link), but never overwrite text the
  // user is typing right now. This is React's "adjust state while rendering" pattern, guarded by a key.
  const urlKey = JSON.stringify(state);
  const [syncedKey, setSyncedKey] = useState(urlKey);
  if (syncedKey !== urlKey) {
    setSyncedKey(urlKey);
    setFilters(pick(state));
    if (!searchFocused) setText(state.q ?? "");
  }

  useEffect(() => () => clearTimeout(timer.current), []);

  function go(next: ListState) {
    clearTimeout(timer.current);
    startTransition(() => router.replace(indicatorListHref(state, { ...next, page: 1 })));
  }

  function onSearchChange(value: string) {
    setText(value);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => go({ ...filters, q: value.trim() }), SEARCH_DELAY_MS);
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    go({ ...filters, q: text.trim() });
  }

  function onSelect(key: FilterKey, value: string) {
    setFilters((current) => ({ ...current, [key]: value }));
    go({ ...filters, [key]: value, q: text.trim() });
  }

  function onSort(sort: string, order: string) {
    go({ ...filters, q: text.trim(), sort, order });
  }

  function clear() {
    setText("");
    setFilters(pick({}));
    go({ q: "", type: "", status: "", verdict: "", severity: "", origin: "", tag: "" });
    input.current?.focus();
  }

  const active = hasActiveFilters({ ...filters, q: text });

  return (
    <form
      role="search"
      aria-label="Search and filter indicators"
      onSubmit={onSubmit}
      className="space-y-3"
    >
      <div className="relative">
        <label htmlFor="indicator-search" className="sr-only">
          Search indicators
        </label>
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"
        />
        <input
          ref={input}
          id="indicator-search"
          type="search"
          value={text}
          onChange={(event) => onSearchChange(event.target.value)}
          onFocus={() => setSearchFocused(true)}
          onBlur={() => setSearchFocused(false)}
          placeholder="Search by value, description, source or tag (all words must match)"
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

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <FilterSelect
          label="Type"
          value={filters.type}
          onChange={(v) => onSelect("type", v)}
          all="All types"
        >
          {INDICATOR_TYPES.map((value) => (
            <option key={value} value={value}>
              {INDICATOR_TYPE_LABELS[value]}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect
          label="Verdict"
          value={filters.verdict}
          onChange={(v) => onSelect("verdict", v)}
          all="Any verdict"
        >
          {VERDICTS.map((value) => (
            <option key={value} value={value}>
              {VERDICT_LABELS[value]}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect
          label="Severity"
          value={filters.severity}
          onChange={(v) => onSelect("severity", v)}
          all="Any severity"
        >
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {SEVERITY_LABELS[value]}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect
          label="Status"
          value={filters.status}
          onChange={(v) => onSelect("status", v)}
          all="Any status"
        >
          {INDICATOR_STATUSES.map((value) => (
            <option key={value} value={value}>
              {INDICATOR_STATUS_LABELS[value]}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect
          label="Origin"
          value={filters.origin}
          onChange={(v) => onSelect("origin", v)}
          all="Any origin"
        >
          {DATA_ORIGINS.map((value) => (
            <option key={value} value={value}>
              {ORIGIN_LABELS[value]}
            </option>
          ))}
        </FilterSelect>
        <FilterSelect
          label="Tag"
          value={filters.tag}
          onChange={(v) => onSelect("tag", v)}
          all="Any tag"
        >
          {/* A tag from the URL that is not in the list (renamed, or typed by hand) stays selectable. */}
          {filters.tag && !tags.some((tag) => tag.toLowerCase() === filters.tag.toLowerCase()) && (
            <option value={filters.tag}>{filters.tag}</option>
          )}
          {tags.map((tag) => (
            <option key={tag} value={tag}>
              {tag}
            </option>
          ))}
        </FilterSelect>
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
              value={state.sort ?? "last_seen"}
              onChange={(event) => onSort(event.target.value, state.order ?? "desc")}
              className="h-9 w-40"
            >
              {INDICATOR_SORT_FIELDS.map((field) => (
                <option key={field} value={field}>
                  {SORT_LABELS[field]}
                </option>
              ))}
            </Select>
          </label>
          <label className="block space-y-1">
            <span className="sr-only">Order</span>
            <Select
              value={state.order ?? "desc"}
              onChange={(event) => onSort(state.sort ?? "last_seen", event.target.value)}
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

function pick(state: ListState): Record<FilterKey, string> {
  return {
    type: state.type ?? "",
    status: state.status ?? "",
    verdict: state.verdict ?? "",
    severity: state.severity ?? "",
    origin: state.origin ?? "",
    tag: state.tag ?? "",
  };
}

function FilterSelect({
  label,
  value,
  onChange,
  all,
  children,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  all: string;
  children: ReactNode;
}) {
  return (
    <label className="block space-y-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      <Select value={value} onChange={(event) => onChange(event.target.value)} className="h-9">
        <option value="">{all}</option>
        {children}
      </Select>
    </label>
  );
}
