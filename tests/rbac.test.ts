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
// Later migrations that are *allowed* to extend the RBAC reference data, because this test reads
// their inserts too. A migration not in this list must not touch roles/permissions/role_permissions
// (see the last test below) — add a migration here only alongside a matching change to
// src/lib/rbac/permissions.ts.
const RBAC_EXTENSION_MIGRATIONS = [
  "20260927130000_ai_foundation.sql",
  "20260928100000_alert_deduplication_and_detection_rules.sql",
  "20260930170000_soc_roles_and_signup_approval.sql",
];
const ALL_RBAC_MIGRATIONS = [RBAC_MIGRATION, ...RBAC_EXTENSION_MIGRATIONS];

/** Extracts `('a', 'b')` string pairs and `('a')` singles from the body of an INSERT statement. */
function insertedTuples(sql: string, table: string): string[][] {
  const match = new RegExp(`insert into public\\.${table}[^;]*?values\\s*([^;]+);`, "is").exec(sql);
  if (!match) return [];
  return [...match[1].matchAll(/\(\s*'([^']*)'(?:\s*,\s*'([^']*)')?/g)].map(([, a, b]) =>
    b === undefined ? [a] : [a, b],
  );
}

/** `update public.roles set name = new ... where name = old` in the extension migrations. */
function roleRenames(): Map<string, string> {
  const renames = new Map<string, string>();
  for (const file of ALL_RBAC_MIGRATIONS) {
    const text = readFileSync(join(migrationsDir, file), "utf8");
    for (const [, next, previous] of text.matchAll(
      /update public\.roles\s+set name = '([^']+)'[^;]*?where name = '([^']+)'/gi,
    )) {
      renames.set(previous, next);
    }
  }
  return renames;
}

/** The same extraction, but merged across every migration allowed to add reference data. */
function allInsertedTuples(table: string): string[][] {
  const renames = roleRenames();
  const rename = (name: string) => renames.get(name) ?? name;
  const tuples = ALL_RBAC_MIGRATIONS.flatMap((file) =>
    insertedTuples(readFileSync(join(migrationsDir, file), "utf8"), table),
  );
  // A later migration may rename a role; the mirror follows the final name.
  if (table === "roles") return tuples.map(([name]) => [rename(name)]);
  if (table === "role_permissions") return tuples.map(([role, key]) => [rename(role), key]);
  return tuples;
}

describe("RBAC mirror stays in sync with the database reference data", () => {
  const sql = readFileSync(join(migrationsDir, RBAC_MIGRATION), "utf8");

  it("has the same roles", () => {
    const dbRoles = allInsertedTuples("roles").map(([name]) => name);
    expect([...dbRoles].sort()).toEqual([...ROLE_NAMES].sort());
  });

  it("has the same permission keys", () => {
    const dbKeys = allInsertedTuples("permissions").map(([key]) => key);
    expect([...dbKeys].sort()).toEqual([...PERMISSIONS].sort());
  });

  it("grants each role the same permissions (admin gets everything)", () => {
    const explicit = allInsertedTuples("role_permissions");
    for (const role of ["soc_l2", "soc_l1", "viewer"] as const) {
      const dbGrants = explicit.filter(([r]) => r === role).map(([, key]) => key);
      expect([...dbGrants].sort()).toEqual([...ROLE_PERMISSIONS[role]].sort());
    }
    expect(sql).toMatch(/select 'admin', key from public\.permissions/);
    // Everything the base migration granted admin via the catch-all, plus every permission an
    // extension migration granted admin explicitly (its catch-all already ran and cannot see them).
    const explicitAdminGrants = explicit.filter(([r]) => r === "admin").map(([, key]) => key);
    for (const key of explicitAdminGrants) {
      expect(ROLE_PERMISSIONS.admin).toContain(key);
    }
    expect([...ROLE_PERMISSIONS.admin].sort()).toEqual([...PERMISSIONS].sort());
  });

  it("is not changed by a later migration without updating the mirror", () => {
    const mutation =
      /(insert\s+into|delete\s+from|update|truncate(?:\s+table)?)\s+(only\s+)?public\.(role_permissions|permissions|roles)\b/i;
    const offenders = readdirSync(migrationsDir)
      .filter((file) => file.endsWith(".sql") && !ALL_RBAC_MIGRATIONS.includes(file))
      .filter((file) => mutation.test(readFileSync(join(migrationsDir, file), "utf8")));
    // If this fails, update src/lib/rbac/permissions.ts, add the migration to
    // RBAC_EXTENSION_MIGRATIONS above, and make sure it only INSERTs (never deletes or updates).
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
      expect(roleHasPermission("soc_l2", permission)).toBe(false);
      expect(roleHasPermission("viewer", permission)).toBe(false);
    }
    expect(roleHasPermission("viewer", "indicators:write")).toBe(false);
    expect(roleHasPermission("soc_l2", "indicators:write")).toBe(true);
    expect(roleHasPermission("soc_l2", "indicators:delete")).toBe(false);
  });

  it("gives L1 triage rights but not case, indicator or admin rights", () => {
    for (const permission of ["alerts:read", "alerts:write", "ai:use"] as const) {
      expect(roleHasPermission("soc_l1", permission)).toBe(true);
    }
    for (const permission of [
      "investigations:write",
      "indicators:write",
      "reports:write",
      "rules:manage",
      "users:manage",
    ] as const) {
      expect(roleHasPermission("soc_l1", permission)).toBe(false);
    }
    // L2 keeps everything L1 can do.
    for (const permission of ROLE_PERMISSIONS.soc_l1) {
      expect(roleHasPermission("soc_l2", permission)).toBe(true);
    }
  });

  it("returns a set of the role's permissions", () => {
    expect(permissionsForRole("viewer").has("indicators:read")).toBe(true);
    expect(permissionsForRole("viewer").size).toBe(ROLE_PERMISSIONS.viewer.length);
  });
});
