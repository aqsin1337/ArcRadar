import type { AlertDetail } from "./types";
import { ALERT_STATUS_LABELS } from "./constants";

export type AlertTimelineEntry = { at: string; title: string; detail: string | null };

/**
 * What happened to an alert, newest first: it was raised, an analyst picked it up, it was closed,
 * and the investigations it was added to. Only what is recorded is shown (there is no per-change
 * history for an alert, unlike an investigation).
 */
export function buildAlertTimeline(
  alert: Pick<
    AlertDetail,
    "created_at" | "acknowledged_at" | "resolved_at" | "status" | "source" | "investigations"
  >,
): AlertTimelineEntry[] {
  const entries: AlertTimelineEntry[] = [
    { at: alert.created_at, title: "Raised", detail: `Source: ${alert.source}` },
  ];
  if (alert.acknowledged_at) {
    entries.push({ at: alert.acknowledged_at, title: "Acknowledged", detail: null });
  }
  if (alert.resolved_at) {
    entries.push({
      at: alert.resolved_at,
      title: `Closed as ${ALERT_STATUS_LABELS[alert.status].toLowerCase()}`,
      detail: null,
    });
  }
  for (const investigation of alert.investigations) {
    entries.push({
      at: investigation.added_at,
      title: "Added to an investigation",
      detail: investigation.title,
    });
  }
  return entries.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}
