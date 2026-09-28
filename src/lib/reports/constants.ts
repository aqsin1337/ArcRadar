import { Constants } from "@/types/database";
import type { ReportType } from "@/types/domain";

export const REPORT_TYPES = Constants.public.Enums.report_type;

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  investigation: "Investigation summary",
  indicators: "Indicator summary",
  alerts: "Alert summary",
  vulnerabilities: "Vulnerability summary",
  threat_actor: "Threat actor activity",
};

export const REPORT_TYPE_DESCRIPTIONS: Record<ReportType, string> = {
  investigation: "One investigation's status, linked records, notes and timeline.",
  alerts: "Alerts by status and severity, and the ones still open.",
  indicators: "Indicators by type and verdict, and the most recently seen malicious ones.",
  vulnerabilities: "Vulnerabilities by severity and which are exploited in the wild.",
  threat_actor: "One threat actor's campaigns, malware, techniques and tracked indicators.",
};

/** Report types that summarize the whole workspace as of now, rather than one record. */
export const WORKSPACE_REPORT_TYPES = ["indicators", "alerts", "vulnerabilities"] as const;
