import type {
  AlertStatus,
  IndicatorType,
  InvestigationStatus,
  Priority,
  Report,
  Severity,
  Verdict,
} from "@/types/domain";

export type ReportListItem = Pick<
  Report,
  "id" | "title" | "type" | "investigation_id" | "origin" | "created_at" | "created_by"
> & { created_by_name: string | null };

/** The generated snapshot, one shape per report type. Computed once at creation time; a report
 * never changes afterwards, so it stays an honest record of what the workspace looked like then. */
export type IndicatorsReportContent = {
  total: number;
  by_type: { type: IndicatorType; total: number }[];
  by_verdict: { verdict: Verdict; total: number }[];
  top_malicious: {
    id: string;
    type: IndicatorType;
    value: string;
    severity: Severity;
    last_seen: string;
  }[];
};

export type AlertsReportContent = {
  total: number;
  by_status: { status: AlertStatus; total: number }[];
  by_severity: { severity: Severity; total: number }[];
  open: {
    id: string;
    title: string;
    severity: Severity;
    status: AlertStatus;
    created_at: string;
  }[];
};

export type VulnerabilitiesReportContent = {
  total: number;
  by_severity: { severity: Severity; total: number; exploited: number }[];
  exploited_in_wild: { cve_id: string; title: string; cvss_score: number | null }[];
};

export type InvestigationReportContent = {
  investigation: {
    id: string;
    title: string;
    status: InvestigationStatus;
    priority: Priority;
    created_at: string;
    updated_at: string;
    analyst: string | null;
  };
  indicators: { id: string; type: IndicatorType; value: string }[];
  alerts: { id: string; title: string; severity: Severity; status: AlertStatus }[];
  notes: { author: string | null; body: string; kind: string; created_at: string }[];
  evidence: { title: string; location: string; created_at: string }[];
};

export type ReportContent =
  | IndicatorsReportContent
  | AlertsReportContent
  | VulnerabilitiesReportContent
  | InvestigationReportContent;

export type ReportDetail = Report & { created_by_name: string | null };
