"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import { REPORT_TYPES, REPORT_TYPE_LABELS } from "@/lib/reports/constants";
import { reportList } from "@/lib/reports/url";
import type { ListState } from "@/lib/validation/list-url";

const SORT = {
  fields: [{ value: "created_at", label: "Newest first" }],
  defaultField: "created_at",
};

const fields: FilterField[] = [
  {
    key: "type",
    label: "Type",
    all: "Any type",
    options: REPORT_TYPES.map((value) => ({ value, label: REPORT_TYPE_LABELS[value] })),
  },
];

export function ReportFilters({ state }: { state: ListState }) {
  return (
    <ListFilters
      ariaLabel="Search and filter reports"
      searchId="report-search"
      searchLabel="Search reports"
      searchPlaceholder="Search by title"
      state={state}
      fields={fields}
      sort={SORT}
      hrefFor={(current, overrides) => reportList.href(current, overrides)}
    />
  );
}
