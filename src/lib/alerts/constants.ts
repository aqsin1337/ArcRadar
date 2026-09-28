import { Constants } from "@/types/database";
import type { AlertStatus } from "@/types/domain";

export const ALERT_STATUSES = Constants.public.Enums.alert_status;

export const ALERT_STATUS_LABELS: Record<AlertStatus, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive",
};

/** Columns the list can be sorted by. Severity sorts by rank (critical first when descending). */
export const ALERT_SORT_FIELDS = ["created_at", "updated_at", "severity", "status"] as const;
export type AlertSortField = (typeof ALERT_SORT_FIELDS)[number];

export const ALERT_SORT_LABELS: Record<AlertSortField, string> = {
  created_at: "Created",
  updated_at: "Last updated",
  severity: "Severity",
  status: "Status",
};

/** Who an alert is assigned to, as a filter: the caller, nobody, or a specific person. */
export const ASSIGNEE_ME = "me";
export const ASSIGNEE_NONE = "none";
