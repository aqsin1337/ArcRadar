import { Constants } from "@/types/database";
import type { DataOrigin, IndicatorStatus, IndicatorType, Severity, Verdict } from "@/types/domain";

// Runtime lists come from the generated database types, so a new enum value in a migration shows up
// here after `npm run db:types` (and TypeScript flags every label map that misses it).
export const INDICATOR_TYPES = Constants.public.Enums.indicator_type;
export const INDICATOR_STATUSES = Constants.public.Enums.indicator_status;
export const SEVERITIES = Constants.public.Enums.severity;
export const VERDICTS = Constants.public.Enums.verdict;
export const DATA_ORIGINS = Constants.public.Enums.data_origin;

export const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  ipv4: "IPv4 address",
  ipv6: "IPv6 address",
  domain: "Domain",
  url: "URL",
  md5: "MD5 hash",
  sha1: "SHA-1 hash",
  sha256: "SHA-256 hash",
  email: "Email address",
  cve: "CVE",
  other: "Other",
};

/** Compact labels for table cells and search results. */
export const INDICATOR_TYPE_SHORT_LABELS: Record<IndicatorType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
  email: "Email",
  cve: "CVE",
  other: "Other",
};

export const INDICATOR_STATUS_LABELS: Record<IndicatorStatus, string> = {
  active: "Active",
  inactive: "Inactive",
  expired: "Expired",
  whitelisted: "Allow-listed",
  under_review: "Under review",
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  unknown: "Unknown",
  benign: "Benign",
  suspicious: "Suspicious",
  malicious: "Malicious",
};

export const ORIGIN_LABELS: Record<DataOrigin, string> = {
  demo: "Demo data",
  local: "Local",
  external: "External provider",
};

/** Columns the list can be sorted by. `value` sorts on the normalized (case-folded) value. */
export const INDICATOR_SORT_FIELDS = [
  "last_seen",
  "first_seen",
  "created_at",
  "updated_at",
  "value",
  "type",
  "severity",
  "verdict",
  "status",
  "confidence",
] as const;
export type IndicatorSortField = (typeof INDICATOR_SORT_FIELDS)[number];

export const SORT_LABELS: Record<IndicatorSortField, string> = {
  last_seen: "Last seen",
  first_seen: "First seen",
  created_at: "Date added",
  updated_at: "Last updated",
  value: "Indicator",
  type: "Type",
  severity: "Severity",
  verdict: "Verdict",
  status: "Status",
  confidence: "Confidence",
};

export const MAX_INDICATOR_TAGS = 20;
export const MAX_TAG_LENGTH = 50;
