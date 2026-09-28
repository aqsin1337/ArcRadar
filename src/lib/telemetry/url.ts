import { createListUrl } from "@/lib/validation/list-url";

/** The events list on the /telemetry page: its filters and paging live in the address. */
export const eventList = createListUrl({
  path: "/telemetry",
  filterKeys: ["source", "severity", "origin"],
  defaultSort: "occurred_at",
});
