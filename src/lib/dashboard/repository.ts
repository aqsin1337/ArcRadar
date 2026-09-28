import "server-only";
import type { AuthClient } from "@/lib/auth/context";
import { toApiError } from "@/lib/api/supabase-errors";
import type {
  ActivityPoint,
  DashboardCounts,
  IndicatorTypeCount,
  IndicatorVerdictCount,
  SeverityCount,
  TopThreatActor,
} from "./types";

const ACTIVE_ALERT_STATUSES = ["new", "acknowledged", "investigating"] as const;
const OPEN_INVESTIGATION_STATUSES = ["open", "investigating", "contained"] as const;

function since(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

/** Head counts only (no rows fetched): cheap, and each respects the caller's own RLS. */
export async function findCounts(supabase: AuthClient, days: number): Promise<DashboardCounts> {
  const cutoff = since(days);
  const head = { count: "exact" as const, head: true };

  const [total, malicious, suspicious, activeAlerts, criticalVulns, openInv, events, recentAlerts] =
    await Promise.all([
      supabase.from("indicators").select("id", head),
      supabase.from("indicators").select("id", head).eq("verdict", "malicious"),
      supabase.from("indicators").select("id", head).eq("verdict", "suspicious"),
      supabase
        .from("alerts")
        .select("id", head)
        .in("status", ACTIVE_ALERT_STATUSES)
        .is("duplicate_of", null),
      supabase.from("vulnerabilities").select("id", head).eq("severity", "critical"),
      supabase.from("investigations").select("id", head).in("status", OPEN_INVESTIGATION_STATUSES),
      supabase.from("events").select("id", head).gte("occurred_at", cutoff),
      supabase.from("alerts").select("id", head).gte("created_at", cutoff).is("duplicate_of", null),
    ]);

  for (const result of [
    total,
    malicious,
    suspicious,
    activeAlerts,
    criticalVulns,
    openInv,
    events,
    recentAlerts,
  ]) {
    if (result.error) throw toApiError(result.error);
  }

  return {
    indicators_total: total.count ?? 0,
    indicators_malicious: malicious.count ?? 0,
    indicators_suspicious: suspicious.count ?? 0,
    alerts_active: activeAlerts.count ?? 0,
    vulnerabilities_critical: criticalVulns.count ?? 0,
    investigations_open: openInv.count ?? 0,
    events_recent: events.count ?? 0,
    alerts_recent: recentAlerts.count ?? 0,
  };
}

export async function findAlertSeverityCounts(supabase: AuthClient): Promise<SeverityCount[]> {
  const { data, error } = await supabase.rpc("alert_severity_counts");
  if (error) throw toApiError(error);
  return data.map((row) => ({ severity: row.severity, total: Number(row.total) }));
}

export async function findIndicatorTypeCounts(supabase: AuthClient): Promise<IndicatorTypeCount[]> {
  const { data, error } = await supabase.rpc("indicator_type_counts");
  if (error) throw toApiError(error);
  return data.map((row) => ({ type: row.type, total: Number(row.total) }));
}

export async function findIndicatorVerdictCounts(
  supabase: AuthClient,
): Promise<IndicatorVerdictCount[]> {
  const { data, error } = await supabase.rpc("indicator_verdict_counts");
  if (error) throw toApiError(error);
  return data.map((row) => ({ verdict: row.verdict, total: Number(row.total) }));
}

export async function findActivity(supabase: AuthClient, days: number): Promise<ActivityPoint[]> {
  const { data, error } = await supabase.rpc("activity_series", { p_days: days });
  if (error) throw toApiError(error);
  return data.map((row) => ({
    day: row.day,
    alerts: Number(row.alerts),
    events: Number(row.events),
  }));
}

export async function findTopThreatActors(
  supabase: AuthClient,
  limit: number,
): Promise<TopThreatActor[]> {
  const { data, error } = await supabase.rpc("top_threat_actors", { p_limit: limit });
  if (error) throw toApiError(error);
  return data.map((row) => ({
    id: row.id,
    name: row.name,
    indicator_count: Number(row.indicator_count),
  }));
}
