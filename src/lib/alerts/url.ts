import { createListUrl } from "@/lib/validation/list-url";

export const alertList = createListUrl({
  path: "/alerts",
  filterKeys: ["q", "status", "severity", "source", "assignee", "origin", "duplicates"],
  defaultSort: "created_at",
});

export const alertListHref = alertList.href;
export const hasActiveAlertFilters = alertList.hasActive;
