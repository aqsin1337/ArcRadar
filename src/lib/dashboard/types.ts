import type { AlertListItem } from "@/lib/alerts/types";
import type { IndicatorListItem } from "@/lib/indicators/types";
import type { InvestigationListItem } from "@/lib/investigations/types";
import type { IndicatorType, Severity, Verdict } from "@/types/domain";

/** Headline numbers. `events_recent` and `alerts_recent` respect the selected date window; the rest
 * are the workspace's real, unfiltered totals (a dashboard that hides the true count to match a
 * filter would be misleading, not useful). */
export type DashboardCounts = {
  indicators_total: number;
  indicators_malicious: number;
  indicators_suspicious: number;
  alerts_active: number;
  vulnerabilities_critical: number;
  investigations_open: number;
  events_recent: number;
  alerts_recent: number;
};

export type SeverityCount = { severity: Severity; total: number };
export type IndicatorTypeCount = { type: IndicatorType; total: number };
export type IndicatorVerdictCount = { verdict: Verdict; total: number };
export type ActivityPoint = { day: string; alerts: number; events: number };
export type TopThreatActor = { id: string; name: string; indicator_count: number };

export type DashboardData = {
  counts: DashboardCounts;
  severity_distribution: SeverityCount[];
  ioc_distribution: IndicatorTypeCount[];
  verdict_distribution: IndicatorVerdictCount[];
  activity: ActivityPoint[];
  top_threat_actors: TopThreatActor[];
  top_malicious_indicators: IndicatorListItem[];
  recent_indicators: IndicatorListItem[];
  recent_alerts: AlertListItem[];
  recent_investigations: InvestigationListItem[];
};
