import { createListUrl } from "@/lib/validation/list-url";

export const investigationList = createListUrl({
  path: "/investigations",
  filterKeys: ["q", "status", "priority", "analyst", "tag", "origin"],
  defaultSort: "updated_at",
});

export const investigationListHref = investigationList.href;
export const hasActiveInvestigationFilters = investigationList.hasActive;
