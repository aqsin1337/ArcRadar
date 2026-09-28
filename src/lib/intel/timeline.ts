import type { IndicatorDetail } from "@/lib/indicators/types";
import type { DataOrigin, IndicatorType, Row, Severity, Verdict } from "@/types/domain";

/** Pure data shapes and the timeline builder: no server-only imports, so the tests can use them directly. */

export type RelatedIndicator = {
  id: string;
  type: IndicatorType;
  value: string;
  verdict: Verdict;
  severity: Severity;
  origin: DataOrigin;
};

export type LocalAlert = Pick<
  Row<"alerts">,
  "id" | "title" | "severity" | "status" | "created_at" | "origin"
>;
export type LocalEvent = Pick<
  Row<"events">,
  "id" | "title" | "severity" | "event_type" | "occurred_at" | "origin"
>;
export type LocalInvestigation = Pick<
  Row<"investigations">,
  "id" | "title" | "status" | "priority" | "created_at" | "origin"
>;

export type TimelineEntry = {
  at: string;
  kind: "first_seen" | "last_seen" | "event" | "alert" | "investigation";
  title: string;
  detail: string | null;
  severity: Severity | null;
  origin: DataOrigin | null;
  /** The record's page, for the entries that have one (alerts and investigations). */
  href: string | null;
};

export type LocalContext = {
  /** The indicator that tracks the subject in this workspace, with its links, or null. */
  indicator: IndicatorDetail | null;
  /** Other indicators that mention the subject (not already shown as relationships). */
  related: RelatedIndicator[];
  alerts: LocalAlert[];
  events: LocalEvent[];
  investigations: LocalInvestigation[];
  timeline: TimelineEntry[];
};

const MAX_TIMELINE = 25;

const humanize = (value: string) => {
  const text = value.replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
};

/** Newest first: sightings of the indicator, its events, alerts and investigations. */
export function buildTimeline(
  context: Pick<LocalContext, "indicator" | "alerts" | "events" | "investigations">,
): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  const { indicator } = context;

  if (indicator) {
    entries.push({
      at: indicator.first_seen,
      kind: "first_seen",
      title: "First seen",
      detail: `Source: ${indicator.source}`,
      severity: null,
      origin: indicator.origin,
      href: null,
    });
    if (indicator.last_seen !== indicator.first_seen) {
      entries.push({
        at: indicator.last_seen,
        kind: "last_seen",
        title: "Last seen",
        detail: null,
        severity: null,
        origin: indicator.origin,
        href: null,
      });
    }
  }
  for (const event of context.events) {
    entries.push({
      at: event.occurred_at,
      kind: "event",
      title: event.title,
      detail: `Event · ${event.event_type}`,
      severity: event.severity,
      origin: event.origin,
      href: null,
    });
  }
  for (const alert of context.alerts) {
    entries.push({
      at: alert.created_at,
      kind: "alert",
      title: alert.title,
      detail: `Alert · ${humanize(alert.status)}`,
      severity: alert.severity,
      origin: alert.origin,
      href: `/alerts/${alert.id}`,
    });
  }
  for (const investigation of context.investigations) {
    entries.push({
      at: investigation.created_at,
      kind: "investigation",
      title: investigation.title,
      detail: `Investigation · ${humanize(investigation.status)}, ${investigation.priority} priority`,
      severity: null,
      origin: investigation.origin,
      href: `/investigations/${investigation.id}`,
    });
  }

  return entries
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at) || a.title.localeCompare(b.title))
    .slice(0, MAX_TIMELINE);
}
