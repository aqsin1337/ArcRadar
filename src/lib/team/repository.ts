import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { isRoleName, roleHasPermission, type Permission } from "@/lib/rbac/permissions";
import type { RoleName } from "@/types/domain";

export type TeamMember = { id: string; display_name: string | null; role: RoleName };

/** This person, if they are active and hold `permission` (someone who may be given work); else null. */
export async function findMember(
  supabase: AuthClient,
  id: string,
  permission: Permission,
): Promise<TeamMember | null> {
  const { data, error } = await supabase
    .from("profiles")
    .select("id, display_name, role_name, is_active")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data || !data.is_active || !isRoleName(data.role_name)) return null;
  return roleHasPermission(data.role_name, permission)
    ? { id: data.id, display_name: data.display_name, role: data.role_name }
    : null;
}

/** Display names for a set of user ids (a missing or hidden profile has no entry). */
export async function findDisplayNames(
  supabase: AuthClient,
  ids: (string | null)[],
): Promise<Map<string, string | null>> {
  const unique = [...new Set(ids.filter((id): id is string => id !== null))];
  const names = new Map<string, string | null>();
  if (unique.length === 0) return names;

  const { data, error } = await supabase
    .from("profiles")
    .select("id, display_name")
    .in("id", unique);
  if (error) throw toApiError(error);
  for (const row of data) names.set(row.id, row.display_name);
  return names;
}

/**
 * Active people who hold `permission` (for example the ones an alert can be assigned to). Active
 * users can see their teammates (the profiles policy), so the caller's own client is enough.
 */
export async function findTeamMembers(
  supabase: AuthClient,
  permission: Permission,
): Promise<TeamMember[]> {
  const { data, error } = await supabase
    .from("profiles")
    .select("id, display_name, role_name")
    .eq("is_active", true)
    .order("display_name");
  if (error) throw toApiError(error);

  return data.flatMap((row) =>
    isRoleName(row.role_name) && roleHasPermission(row.role_name, permission)
      ? [{ id: row.id, display_name: row.display_name, role: row.role_name }]
      : [],
  );
}
