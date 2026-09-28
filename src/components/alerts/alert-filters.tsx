"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import {
  ALERT_SORT_FIELDS,
  ALERT_SORT_LABELS,
  ALERT_STATUSES,
  ALERT_STATUS_LABELS,
  ASSIGNEE_ME,
  ASSIGNEE_NONE,
} from "@/lib/alerts/constants";
import { alertListHref } from "@/lib/alerts/url";
import {
  DATA_ORIGINS,
  ORIGIN_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
} from "@/lib/indicators/constants";
import { personLabel } from "@/lib/format";

type Person = { id: string; display_name: string | null };

const SORT = {
  fields: ALERT_SORT_FIELDS.map((field) => ({ value: field, label: ALERT_SORT_LABELS[field] })),
  defaultField: "created_at",
};

/** Search box and filter menus for the alert list; the URL is the state. */
export function AlertFilters({
  state,
  sources,
  people,
}: {
  state: Record<string, string | number | undefined>;
  sources: string[];
  people: Person[];
}) {
  const fields: FilterField[] = [
    {
      key: "status",
      label: "Status",
      all: "Any status",
      options: ALERT_STATUSES.map((value) => ({ value, label: ALERT_STATUS_LABELS[value] })),
    },
    {
      key: "severity",
      label: "Severity",
      all: "Any severity",
      options: SEVERITIES.map((value) => ({ value, label: SEVERITY_LABELS[value] })),
    },
    {
      key: "assignee",
      label: "Assigned to",
      all: "Anyone",
      options: [
        { value: ASSIGNEE_ME, label: "Me" },
        { value: ASSIGNEE_NONE, label: "Nobody (unassigned)" },
        ...people.map((person) => ({ value: person.id, label: personLabel(person) })),
      ],
    },
    {
      key: "source",
      label: "Source",
      all: "Any source",
      // A source from the URL that no alert has any more stays selectable.
      options: (typeof state.source === "string" && state.source && !sources.includes(state.source)
        ? [state.source, ...sources]
        : sources
      ).map((source) => ({ value: source, label: source })),
    },
    {
      key: "origin",
      label: "Origin",
      all: "Any origin",
      options: DATA_ORIGINS.map((value) => ({ value, label: ORIGIN_LABELS[value] })),
    },
    {
      key: "duplicates",
      label: "Duplicates",
      all: "Hide duplicates",
      options: [{ value: "show", label: "Show duplicates too" }],
    },
  ];

  return (
    <ListFilters
      ariaLabel="Search and filter alerts"
      searchId="alert-search"
      searchLabel="Search alerts"
      searchPlaceholder="Search by title, description, source or indicator (all words must match)"
      state={state}
      fields={fields}
      sort={SORT}
      hrefFor={(current, overrides) => alertListHref(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-6"
    />
  );
}
