import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  isRoleName,
  permissionsForRole,
  roleHasPermission,
} from "@/lib/rbac/permissions";
import { ROLE_NAMES } from "@/types/domain";

const migrationsDir = join(process.cwd(), "supabase", "migrations");
const RBAC_MIGRATION = "20260925100100_rbac_profiles.sql";

/** Extracts `('a', 'b')` string pairs and `('a')` singles from the body of an INSERT statement. */
function insertedTuples(sql: string, table: string): string[][] {
  const match = new RegExp(`insert into public\\.${table}[^;]*?values\\s*([^;]+);`, "is").exec(sql);
  if (!match) throw new Error(`No INSERT for ${table} in ${RBAC_MIGRATION}`);
  return [...match[1].matchAll(/\(\s*'([^']*)'(?:\s*,\s*'([^']*)')?/g)].map(([, a, b]) =>
    b === undefined ? [a] : [a, b],
  );
}

describe("RBAC mirror stays in sync with the database reference data", () => {
  const sql = readFileSync(join(migrationsDir, RBAC_MIGRATION), "utf8");

  it("has the same roles", () => {
    const dbRoles = insertedTuples(sql, "roles").map(([name]) => name);
    expect([...dbRoles].sort()).toEqual([...ROLE_NAMES].sort());
  });

  it("has the same permission keys", () => {
    const dbKeys = insertedTuples(sql, "permissions").map(([key]) => key);
    expect([...dbKeys].sort()).toEqual([...PERMISSIONS].sort());
  });

  it("grants each role the same permissions (admin gets everything)", () => {
    const explicit = insertedTuples(sql, "role_permissions");
    for (const role of ["analyst", "viewer"] as const) {
      const dbGrants = explicit.filter(([r]) => r === role).map(([, key]) => key);
      expect([...dbGrants].sort()).toEqual([...ROLE_PERMISSIONS[role]].sort());
    }
    expect(sql).toMatch(/select 'admin', key from public\.permissions/);
    expect([...ROLE_PERMISSIONS.admin].sort()).toEqual([...PERMISSIONS].sort());
  });

  it("is not changed by a later migration without updating the mirror", () => {
    const mutation =
      /(insert\s+into|delete\s+from|update|truncate(?:\s+table)?)\s+(only\s+)?public\.(role_permissions|permissions|roles)\b/i;
    const offenders = readdirSync(migrationsDir)
      .filter((file) => file.endsWith(".sql") && file !== RBAC_MIGRATION)
      .filter((file) => mutation.test(readFileSync(join(migrationsDir, file), "utf8")));
    // If this fails, update src/lib/rbac/permissions.ts and extend this test to read the change.
    expect(offenders).toEqual([]);
  });
});

describe("role helpers", () => {
  it("recognizes only the known roles", () => {
    expect(isRoleName("admin")).toBe(true);
    expect(isRoleName("superuser")).toBe(false);
    expect(isRoleName(undefined)).toBe(false);
  });

  it("keeps privileged permissions away from analysts and viewers", () => {
    for (const permission of ["audit:read", "users:manage", "settings:manage"] as const) {
      expect(roleHasPermission("admin", permission)).toBe(true);
      expect(roleHasPermission("analyst", permission)).toBe(false);
      expect(roleHasPermission("viewer", permission)).toBe(false);
    }
    expect(roleHasPermission("viewer", "indicators:write")).toBe(false);
    expect(roleHasPermission("analyst", "indicators:write")).toBe(true);
    expect(roleHasPermission("analyst", "indicators:delete")).toBe(false);
  });

  it("returns a set of the role's permissions", () => {
    expect(permissionsForRole("viewer").has("indicators:read")).toBe(true);
    expect(permissionsForRole("viewer").size).toBe(ROLE_PERMISSIONS.viewer.length);
  });
});
