import "server-only";
import { alertListQuerySchema } from "@/lib/alerts/schema";
import { getAlertStats, listAlerts } from "@/lib/alerts/service";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import {
  findAlertSeverityCounts,
  findIndicatorTypeCounts,
  findIndicatorVerdictCounts,
} from "@/lib/dashboard/repository";
import { indicatorListQuerySchema } from "@/lib/indicators/schema";
import { listIndicators } from "@/lib/indicators/service";
import { getInvestigation } from "@/lib/investigations/service";
import { findDisplayNames } from "@/lib/team/repository";
import { getActor } from "@/lib/threat-intel/service";
import { vulnerabilityListQuerySchema } from "@/lib/vulnerabilities/schema";
import { getVulnerabilityStats, listVulnerabilities } from "@/lib/vulnerabilities/service";
import type { Json } from "@/types/database";
import type { Report } from "@/types/domain";
import { deleteReportRow, findReport, findReports, insertReport } from "./repository";
import { reportIdSchema, type CreateReportInput, type ReportListQuery } from "./schema";
import type {
  AlertsReportContent,
  IndicatorsReportContent,
  InvestigationReportContent,
  ReportContent,
  ReportDetail,
  ReportListItem,
  ThreatActorReportContent,
  VulnerabilitiesReportContent,
} from "./types";

type RequestLike = { headers: Headers };

const TOP_LIMIT = 10;
const stamp = () => new Date().toISOString().slice(0, 10);
export const isReportId = (id: string) => reportIdSchema.safeParse(id).success;

async function buildContent(
  auth: AuthContext,
  input: CreateReportInput,
): Promise<{ content: ReportContent; title: string; investigation_id: string | null }> {
  switch (input.type) {
    case "investigation": {
      const inv = await getInvestigation(auth.supabase, input.investigation_id);
      const content: InvestigationReportContent = {
        investigation: {
          id: inv.id,
          title: inv.title,
          status: inv.status,
          priority: inv.priority,
          created_at: inv.created_at,
          updated_at: inv.updated_at,
          analyst: inv.analyst?.display_name ?? null,
        },
        indicators: inv.indicators.map((i) => ({ id: i.id, type: i.type, value: i.value })),
        alerts: inv.alerts.map((a) => ({
          id: a.id,
          title: a.title,
          severity: a.severity,
          status: a.status,
        })),
        notes: inv.notes.map((n) => ({
          author: n.author_name,
          body: n.body,
          kind: n.kind,
          created_at: n.created_at,
        })),
        evidence: inv.evidence.map((e) => ({
          title: e.title,
          location: e.location,
          created_at: e.created_at,
        })),
      };
      return {
        content,
        title: input.title ?? `Investigation report: ${inv.title}`,
        investigation_id: inv.id,
      };
    }

    case "threat_actor": {
      const actor = await getActor(auth.supabase, input.threat_actor_id);
      const content: ThreatActorReportContent = {
        actor: {
          id: actor.id,
          name: actor.name,
          description: actor.description,
          motivation: actor.motivation,
        },
        campaigns: actor.campaigns.map((c) => ({ id: c.id, name: c.name, status: c.status })),
        malware: actor.malware.map((m) => ({
          id: m.id,
          name: m.name,
          malware_type: m.malware_type,
        })),
        techniques: actor.techniques.map((t) => ({ id: t.id, name: t.name })),
        indicator_count: actor.indicators.total,
      };
      return {
        content,
        title: input.title ?? `Threat actor activity: ${actor.name}`,
        investigation_id: null,
      };
    }

    case "indicators": {
      const [byType, byVerdict, top] = await Promise.all([
        findIndicatorTypeCounts(auth.supabase),
        findIndicatorVerdictCounts(auth.supabase),
        listIndicators(
          auth.supabase,
          indicatorListQuerySchema.parse({
            verdict: "malicious",
            sort: "last_seen",
            order: "desc",
            page_size: TOP_LIMIT,
          }),
        ),
      ]);
      const content: IndicatorsReportContent = {
        total: byType.reduce((sum, row) => sum + row.total, 0),
        by_type: byType.map((row) => ({ type: row.type, total: row.total })),
        by_verdict: byVerdict.map((row) => ({ verdict: row.verdict, total: row.total })),
        top_malicious: top.items.map((i) => ({
          id: i.id,
          type: i.type,
          value: i.value,
          severity: i.severity,
          last_seen: i.last_seen,
        })),
      };
      return {
        content,
        title: input.title ?? `Indicator summary — ${stamp()}`,
        investigation_id: null,
      };
    }

    case "alerts": {
      const [stats, bySeverity, open] = await Promise.all([
        getAlertStats(auth.supabase),
        findAlertSeverityCounts(auth.supabase),
        listAlerts(
          auth,
          alertListQuerySchema.parse({ sort: "created_at", order: "desc", page_size: TOP_LIMIT }),
        ),
      ]);
      const content: AlertsReportContent = {
        total: stats.total,
        by_status: stats.by_status.map((row) => ({ status: row.status, total: row.total })),
        by_severity: bySeverity.map((row) => ({ severity: row.severity, total: row.total })),
        open: open.items
          .filter((a) => a.status !== "resolved" && a.status !== "false_positive")
          .map((a) => ({
            id: a.id,
            title: a.title,
            severity: a.severity,
            status: a.status,
            created_at: a.created_at,
          })),
      };
      return {
        content,
        title: input.title ?? `Alert summary — ${stamp()}`,
        investigation_id: null,
      };
    }

    case "vulnerabilities": {
      const [stats, exploited] = await Promise.all([
        getVulnerabilityStats(auth.supabase),
        listVulnerabilities(
          auth.supabase,
          vulnerabilityListQuerySchema.parse({
            exploit_status: "exploited_in_wild",
            page_size: TOP_LIMIT,
          }),
        ),
      ]);
      const content: VulnerabilitiesReportContent = {
        total: stats.total,
        by_severity: stats.by_severity,
        exploited_in_wild: exploited.items.map((v) => ({
          cve_id: v.cve_id,
          title: v.title,
          cvss_score: v.cvss_score,
        })),
      };
      return {
        content,
        title: input.title ?? `Vulnerability summary — ${stamp()}`,
        investigation_id: null,
      };
    }
  }
}

export async function createReport(
  auth: AuthContext,
  input: CreateReportInput,
  request: RequestLike,
): Promise<ReportDetail> {
  const { content, title, investigation_id } = await buildContent(auth, input);
  const row = await insertReport(auth.supabase, {
    title,
    type: input.type,
    investigation_id,
    parameters: input as unknown as NonNullable<Json>,
    content: content as unknown as NonNullable<Json>,
  });

  await writeAuditLog(
    {
      action: "report.created",
      userId: auth.user.id,
      entityType: "report",
      entityId: row.id,
      metadata: { type: row.type, title: row.title },
    },
    request,
  );

  return { ...row, created_by_name: auth.profile.display_name };
}

export async function listReports(
  auth: AuthContext,
  query: ReportListQuery,
): Promise<Page<ReportListItem>> {
  const { rows, total } = await findReports(auth.supabase, query);
  const names = await findDisplayNames(
    auth.supabase,
    rows.map((r) => r.created_by),
  );
  const items = rows.map((r) => ({
    id: r.id,
    title: r.title,
    type: r.type,
    investigation_id: r.investigation_id,
    origin: r.origin,
    created_at: r.created_at,
    created_by: r.created_by,
    created_by_name: r.created_by ? (names.get(r.created_by) ?? null) : null,
  }));
  return buildPage(items, total, query);
}

async function requireReport(auth: AuthContext, id: string): Promise<Report> {
  if (!isReportId(id)) throw apiErrors.notFound("Report not found.");
  const row = await findReport(auth.supabase, id);
  if (!row) throw apiErrors.notFound("Report not found.");
  return row;
}

export async function getReport(auth: AuthContext, id: string): Promise<ReportDetail> {
  const row = await requireReport(auth, id);
  const names = await findDisplayNames(auth.supabase, [row.created_by]);
  return { ...row, created_by_name: row.created_by ? (names.get(row.created_by) ?? null) : null };
}

export async function deleteReport(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  const row = await requireReport(auth, id);
  const removed = await deleteReportRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Report not found.");

  await writeAuditLog(
    {
      action: "report.deleted",
      userId: auth.user.id,
      entityType: "report",
      entityId: id,
      metadata: { type: row.type, title: row.title },
    },
    request,
  );
}
