import "server-only";
import { alertListQuerySchema } from "@/lib/alerts/schema";
import { listAlerts } from "@/lib/alerts/service";
import type { AuthContext } from "@/lib/auth/context";
import { indicatorListQuerySchema } from "@/lib/indicators/schema";
import { listIndicators } from "@/lib/indicators/service";
import { investigationListQuerySchema } from "@/lib/investigations/schema";
import { listInvestigations } from "@/lib/investigations/service";
import type { DashboardQuery } from "./schema";
import {
  findActivity,
  findAlertSeverityCounts,
  findCounts,
  findIndicatorTypeCounts,
  findIndicatorVerdictCounts,
  findTopThreatActors,
} from "./repository";
import type { DashboardData } from "./types";

const RECENT_LIMIT = 6;
const TOP_LIMIT = 5;

/**
 * Everything the Overview page shows, gathered in parallel. `days` bounds the activity chart and
 * the "recent" panels; `severity`, when set, narrows the recent alerts and indicators panels to
 * that severity. The headline counts are always the workspace's true totals (see `DashboardCounts`).
 */
export async function getDashboardData(
  auth: AuthContext,
  { days, severity }: DashboardQuery,
): Promise<DashboardData> {
  const [
    counts,
    severity_distribution,
    ioc_distribution,
    verdict_distribution,
    activity,
    top_threat_actors,
    topMalicious,
    recentIndicators,
    recentAlerts,
    recentInvestigations,
  ] = await Promise.all([
    findCounts(auth.supabase, days),
    findAlertSeverityCounts(auth.supabase),
    findIndicatorTypeCounts(auth.supabase),
    findIndicatorVerdictCounts(auth.supabase),
    findActivity(auth.supabase, days),
    findTopThreatActors(auth.supabase, TOP_LIMIT),
    listIndicators(
      auth.supabase,
      indicatorListQuerySchema.parse({
        verdict: "malicious",
        severity,
        sort: "last_seen",
        order: "desc",
        page_size: TOP_LIMIT,
      }),
    ),
    listIndicators(
      auth.supabase,
      indicatorListQuerySchema.parse({
        severity,
        sort: "last_seen",
        order: "desc",
        page_size: RECENT_LIMIT,
      }),
    ),
    listAlerts(
      auth,
      alertListQuerySchema.parse({
        severity,
        sort: "created_at",
        order: "desc",
        page_size: RECENT_LIMIT,
      }),
    ),
    listInvestigations(
      auth,
      investigationListQuerySchema.parse({
        sort: "updated_at",
        order: "desc",
        page_size: RECENT_LIMIT,
      }),
    ),
  ] as const);

  return {
    counts,
    severity_distribution,
    ioc_distribution,
    verdict_distribution,
    activity,
    top_threat_actors,
    top_malicious_indicators: topMalicious.items,
    recent_indicators: recentIndicators.items,
    recent_alerts: recentAlerts.items,
    recent_investigations: recentInvestigations.items,
  };
}
