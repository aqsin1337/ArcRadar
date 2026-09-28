import { Constants } from "@/types/database";
import type { InvestigationStatus, Priority } from "@/types/domain";

export const INVESTIGATION_STATUSES = Constants.public.Enums.investigation_status;
export const PRIORITIES = Constants.public.Enums.priority;

export const INVESTIGATION_STATUS_LABELS: Record<InvestigationStatus, string> = {
  open: "Open",
  investigating: "Investigating",
  contained: "Contained",
  resolved: "Resolved",
  closed: "Closed",
};

export const PRIORITY_LABELS: Record<Priority, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/** Columns the list can be sorted by. Priority sorts by rank (critical first when descending). */
export const INVESTIGATION_SORT_FIELDS = [
  "updated_at",
  "created_at",
  "priority",
  "status",
  "title",
] as const;
export type InvestigationSortField = (typeof INVESTIGATION_SORT_FIELDS)[number];

export const INVESTIGATION_SORT_LABELS: Record<InvestigationSortField, string> = {
  updated_at: "Last updated",
  created_at: "Created",
  priority: "Priority",
  status: "Status",
  title: "Title",
};

/** Most severe first, the order the tiles use for status counts is the lifecycle order instead. */
export const MAX_LINKED_INDICATORS = 50;
export const MAX_LINKED_ALERTS = 20;
