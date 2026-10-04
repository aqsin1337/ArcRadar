import { Constants } from "@/types/database";
import type { ExploitStatus, Severity } from "@/types/domain";

export const EXPLOIT_STATUSES = Constants.public.Enums.exploit_status;

export const EXPLOIT_STATUS_LABELS: Record<ExploitStatus, string> = {
  unknown: "Unknown",
  none: "No known exploit",
  poc_available: "Proof of concept available",
  exploited_in_wild: "Exploited in the wild",
};

/** Columns the list can be sorted by. Records without a score or date always sort last. */
export const VULNERABILITY_SORT_FIELDS = [
  "published_at",
  "modified_at",
  "cvss_score",
  "severity",
  "cve_id",
] as const;
export type VulnerabilitySortField = (typeof VULNERABILITY_SORT_FIELDS)[number];

export const VULNERABILITY_SORT_LABELS: Record<VulnerabilitySortField, string> = {
  published_at: "Published",
  modified_at: "Modified",
  cvss_score: "CVSS score",
  severity: "Severity",
  cve_id: "CVE id",
};

/** Most severe first, the order statistics are shown in. */
export const SEVERITIES_BY_RANK: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const MAX_AFFECTED_PRODUCTS = 50;
export const MAX_REFERENCES = 50;
