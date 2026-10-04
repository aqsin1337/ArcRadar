"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import {
  DATA_ORIGINS,
  INDICATOR_SORT_FIELDS,
  INDICATOR_STATUSES,
  INDICATOR_STATUS_LABELS,
  INDICATOR_TYPES,
  INDICATOR_TYPE_LABELS,
  ORIGIN_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
  SORT_LABELS,
  VERDICTS,
  VERDICT_LABELS,
} from "@/lib/indicators/constants";
import { indicatorListHref, type ListState } from "@/lib/indicators/url";

const options = <T extends string>(values: readonly T[], labels: Record<T, string>) =>
  values.map((value) => ({ value, label: labels[value] }));

const SORT = {
  fields: INDICATOR_SORT_FIELDS.map((field) => ({ value: field, label: SORT_LABELS[field] })),
  defaultField: "last_seen",
};

/**
 * Search box and filter menus for the indicator list (see `ListFilters` for how they behave): the
 * URL is the state, typing is debounced and every change goes back to page 1.
 */
export function IndicatorFilters({ state, tags }: { state: ListState; tags: string[] }) {
  // A tag from the URL that is not in the list (renamed, or typed by hand) stays selectable.
  const tagOptions =
    state.tag && !tags.some((tag) => tag.toLowerCase() === state.tag?.toLowerCase())
      ? [state.tag, ...tags]
      : tags;

  const fields: FilterField[] = [
    {
      key: "type",
      label: "Type",
      all: "All types",
      options: options(INDICATOR_TYPES, INDICATOR_TYPE_LABELS),
    },
    {
      key: "verdict",
      label: "Verdict",
      all: "Any verdict",
      options: options(VERDICTS, VERDICT_LABELS),
    },
    {
      key: "severity",
      label: "Severity",
      all: "Any severity",
      options: options(SEVERITIES, SEVERITY_LABELS),
    },
    {
      key: "status",
      label: "Status",
      all: "Any status",
      options: options(INDICATOR_STATUSES, INDICATOR_STATUS_LABELS),
    },
    {
      key: "origin",
      label: "Origin",
      all: "Any origin",
      options: options(DATA_ORIGINS, ORIGIN_LABELS),
    },
    {
      key: "tag",
      label: "Tag",
      all: "Any tag",
      options: tagOptions.map((tag) => ({ value: tag, label: tag })),
    },
  ];

  return (
    <ListFilters
      ariaLabel="Search and filter indicators"
      searchId="indicator-search"
      searchLabel="Search indicators"
      searchPlaceholder="Search by value, description, source or tag (all words must match)"
      state={state}
      fields={fields}
      sort={SORT}
      hrefFor={(current, overrides) => indicatorListHref(current, overrides)}
    />
  );
}
