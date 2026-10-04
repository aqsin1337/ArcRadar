"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import { ASSIGNEE_ME, ASSIGNEE_NONE } from "@/lib/alerts/constants";
import { personLabel } from "@/lib/format";
import { DATA_ORIGINS, ORIGIN_LABELS } from "@/lib/indicators/constants";
import {
  INVESTIGATION_SORT_FIELDS,
  INVESTIGATION_SORT_LABELS,
  INVESTIGATION_STATUSES,
  INVESTIGATION_STATUS_LABELS,
  PRIORITIES,
  PRIORITY_LABELS,
} from "@/lib/investigations/constants";
import { investigationListHref } from "@/lib/investigations/url";

type Person = { id: string; display_name: string | null };

const SORT = {
  fields: INVESTIGATION_SORT_FIELDS.map((field) => ({
    value: field,
    label: INVESTIGATION_SORT_LABELS[field],
  })),
  defaultField: "updated_at",
};

/** Search box and filter menus for the investigation list; the URL is the state. */
export function InvestigationFilters({
  state,
  tags,
  people,
}: {
  state: Record<string, string | number | undefined>;
  tags: string[];
  people: Person[];
}) {
  const tag = typeof state.tag === "string" ? state.tag : "";
  const tagOptions =
    tag && !tags.some((known) => known.toLowerCase() === tag.toLowerCase()) ? [tag, ...tags] : tags;

  const fields: FilterField[] = [
    {
      key: "status",
      label: "Status",
      all: "Any status",
      options: INVESTIGATION_STATUSES.map((value) => ({
        value,
        label: INVESTIGATION_STATUS_LABELS[value],
      })),
    },
    {
      key: "priority",
      label: "Priority",
      all: "Any priority",
      options: PRIORITIES.map((value) => ({ value, label: PRIORITY_LABELS[value] })),
    },
    {
      key: "analyst",
      label: "Analyst",
      all: "Anyone",
      options: [
        { value: ASSIGNEE_ME, label: "Me" },
        { value: ASSIGNEE_NONE, label: "Nobody (unassigned)" },
        ...people.map((person) => ({ value: person.id, label: personLabel(person) })),
      ],
    },
    {
      key: "tag",
      label: "Tag",
      all: "Any tag",
      options: tagOptions.map((name) => ({ value: name, label: name })),
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
      ariaLabel="Search and filter investigations"
      searchId="investigation-search"
      searchLabel="Search investigations"
      searchPlaceholder="Search by title, description, tag or attached indicator (all words must match)"
      state={state}
      fields={fields}
      sort={SORT}
      hrefFor={(current, overrides) => investigationListHref(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
    />
  );
}
