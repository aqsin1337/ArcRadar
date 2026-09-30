import type { Database } from "./database";

// Shared domain types derived from the database schema (regenerate with `npm run db:types`).
type PublicSchema = Database["public"];
type TableName = keyof PublicSchema["Tables"];
type EnumName = keyof PublicSchema["Enums"];

export type Row<T extends TableName> = PublicSchema["Tables"][T]["Row"];
export type Insert<T extends TableName> = PublicSchema["Tables"][T]["Insert"];
export type Update<T extends TableName> = PublicSchema["Tables"][T]["Update"];
type EnumValue<T extends EnumName> = PublicSchema["Enums"][T];

export type DataOrigin = EnumValue<"data_origin">;
export type Severity = EnumValue<"severity">;
export type Verdict = EnumValue<"verdict">;
export type Priority = EnumValue<"priority">;
export type IndicatorType = EnumValue<"indicator_type">;
export type IndicatorStatus = EnumValue<"indicator_status">;
export type RelationshipType = EnumValue<"relationship_type">;
export type ExploitStatus = EnumValue<"exploit_status">;
export type AlertStatus = EnumValue<"alert_status">;
export type InvestigationStatus = EnumValue<"investigation_status">;
export type ReportType = EnumValue<"report_type">;

export type Profile = Row<"profiles">;
export type Indicator = Row<"indicators">;
export type MitreTechnique = Row<"mitre_techniques">;
export type Asset = Row<"assets">;
export type Vulnerability = Row<"vulnerabilities">;
export type SecurityEvent = Row<"events">;
export type Alert = Row<"alerts">;
export type Investigation = Row<"investigations">;
export type InvestigationNote = Row<"investigation_notes">;
export type Report = Row<"reports">;
export type Integration = Row<"integrations">;
export type AuditLogEntry = Row<"audit_logs">;

export const ROLE_NAMES = ["admin", "soc_l2", "soc_l1", "viewer"] as const;
export type RoleName = (typeof ROLE_NAMES)[number];

/** What a person sees for a role. The stored name is a slug; the label is for screens and reports. */
export const ROLE_LABELS: Record<RoleName, string> = {
  admin: "Admin",
  soc_l2: "SOC L2",
  soc_l1: "SOC L1",
  viewer: "Viewer",
};

export function roleLabel(role: string): string {
  return (ROLE_LABELS as Record<string, string>)[role] ?? role;
}

/** UI labels for provenance. Demo and local data must never be presented as live intelligence. */
export const DATA_ORIGIN_LABELS: Record<DataOrigin, string> = {
  demo: "Demo data",
  local: "Local",
  external: "External provider",
};
