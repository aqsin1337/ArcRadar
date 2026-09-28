import { createListUrl } from "@/lib/validation/list-url";

/** The reports list keeps its filter and paging state in the address, like every other list page. */
export const reportList = createListUrl({
  path: "/reports",
  filterKeys: ["q", "type"],
  defaultSort: "created_at",
});
