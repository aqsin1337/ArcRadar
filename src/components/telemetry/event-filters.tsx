"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import {
  DATA_ORIGINS,
  ORIGIN_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
} from "@/lib/indicators/constants";
import { EVENT_SORT_FIELDS } from "@/lib/telemetry/constants";
import { eventList } from "@/lib/telemetry/url";

const SORT_LABELS: Record<(typeof EVENT_SORT_FIELDS)[number], string> = {
  occurred_at: "When it happened",
  created_at: "When it was received",
  severity: "Severity",
};

const SORT = {
  fields: EVENT_SORT_FIELDS.map((field) => ({ value: field, label: SORT_LABELS[field] })),
  defaultField: "occurred_at",
};

/** Filter menus for the events list (no text search); the address is the state. */
export function EventFilters({
  state,
  sources,
}: {
  state: Record<string, string | number | undefined>;
  sources: string[];
}) {
  const fields: FilterField[] = [
    {
      key: "source",
      label: "Source",
      all: "Any source",
      // A source from the address that has no events any more stays selectable.
      options: (typeof state.source === "string" && state.source && !sources.includes(state.source)
        ? [state.source, ...sources]
        : sources
      ).map((source) => ({ value: source, label: source })),
    },
    {
      key: "severity",
      label: "Severity",
      all: "Any severity",
      options: SEVERITIES.map((value) => ({ value, label: SEVERITY_LABELS[value] })),
    },
    {
      key: "origin",
      label: "Origin",
      all: "Any origin",
      options: DATA_ORIGINS.map((value) => ({ value, label: ORIGIN_LABELS[value] })),
    },
  ];

  return (
    <ListFilters
      ariaLabel="Filter events"
      searchId="event-search"
      searchLabel="Search events"
      searchPlaceholder=""
      showSearch={false}
      state={state}
      fields={fields}
      sort={SORT}
      hrefFor={(current, overrides) => `${eventList.href(current, overrides)}#events`}
      gridClassName="grid-cols-2 sm:grid-cols-3"
    />
  );
}
