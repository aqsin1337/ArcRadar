import { Constants } from "@/types/database";
import type { ReportType } from "@/types/domain";

/**
 * The report types a person can generate. The database enum still has "threat_actor" (a Postgres
 * enum value cannot be removed), but threat actors no longer exist in ArcRadar, so it is not offered.
 */
export type OfferedReportType = Exclude<ReportType, "threat_actor">;

export const REPORT_TYPES = Constants.public.Enums.report_type.filter(
  (type): type is OfferedReportType => type !== "threat_actor",
);

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  investigation: "Investigation summary",
  indicators: "Indicator summary",
  alerts: "Alert summary",
  vulnerabilities: "Vulnerability summary",
  threat_actor: "Threat actor activity (retired)",
};

export const REPORT_TYPE_DESCRIPTIONS: Record<ReportType, string> = {
  investigation: "One investigation's status, linked records, notes and timeline.",
  alerts: "Alerts by status and severity, and the ones still open.",
  indicators: "Indicators by type and verdict, and the most recently seen malicious ones.",
  vulnerabilities: "Vulnerabilities by severity and which are exploited in the wild.",
  threat_actor: "Retired: threat actors are no longer part of ArcRadar.",
};

/** Report types that summarize the whole workspace as of now, rather than one record. */
export const WORKSPACE_REPORT_TYPES = ["indicators", "alerts", "vulnerabilities"] as const;
