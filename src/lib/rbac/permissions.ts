import { ROLE_NAMES, type RoleName } from "@/types/domain";

/**
 * Application-side mirror of the RBAC reference data in migration 20260925100100. The database is
 * the source of truth: RLS policies call has_permission('<key>'), so these lists only drive early
 * rejection (guards) and UI decisions. tests/rbac.test.ts fails when the two drift apart.
 */
export const PERMISSIONS = [
  "indicators:read",
  "indicators:write",
  "indicators:delete",
  "threat_intel:read",
  "threat_intel:write",
  "vulnerabilities:read",
  "vulnerabilities:write",
  "events:read",
  "events:write",
  "alerts:read",
  "alerts:write",
  "alerts:delete",
  "investigations:read",
  "investigations:write",
  "investigations:delete",
  "reports:read",
  "reports:write",
  "integrations:read",
  "integrations:manage",
  "api_keys:manage_own",
  "api_keys:manage_all",
  "audit:read",
  "users:read",
  "users:manage",
  "settings:manage",
  "ai:use",
  "ai:manage",
  "rules:manage",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const VIEWER_PERMISSIONS = [
  "indicators:read",
  "threat_intel:read",
  "vulnerabilities:read",
  "events:read",
  "alerts:read",
  "investigations:read",
  "reports:read",
] as const satisfies readonly Permission[];

/** Tier 2: investigates, opens cases, writes indicators and reports. */
const SOC_L2_PERMISSIONS = [
  "indicators:read",
  "indicators:write",
  "threat_intel:read",
  "vulnerabilities:read",
  "events:read",
  "alerts:read",
  "alerts:write",
  "investigations:read",
  "investigations:write",
  "reports:read",
  "reports:write",
  "integrations:read",
  "api_keys:manage_own",
  "ai:use",
] as const satisfies readonly Permission[];

/** Tier 1: triages alerts (acknowledge, false positive, assign) and uses AI; cannot open cases. */
const SOC_L1_PERMISSIONS = [
  ...VIEWER_PERMISSIONS,
  "alerts:write",
  "ai:use",
] as const satisfies readonly Permission[];

export const ROLE_PERMISSIONS: Readonly<Record<RoleName, readonly Permission[]>> = {
  admin: PERMISSIONS,
  soc_l2: SOC_L2_PERMISSIONS,
  soc_l1: SOC_L1_PERMISSIONS,
  viewer: VIEWER_PERMISSIONS,
};

export function isRoleName(value: unknown): value is RoleName {
  return typeof value === "string" && (ROLE_NAMES as readonly string[]).includes(value);
}

export function permissionsForRole(role: RoleName): ReadonlySet<Permission> {
  return new Set(ROLE_PERMISSIONS[role]);
}

export function roleHasPermission(role: RoleName, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
