import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import { createAdminClient } from "@/lib/supabase/admin";
import { isRoleName } from "@/lib/rbac/permissions";
import type { RoleName } from "@/types/domain";
import type { AdminUser } from "./types";

const PAGE_SIZE = 200;
const MAX_PAGES = 10; // 2,000 accounts is far beyond this portfolio's scale; a hard stop, not a limit users hit.

/**
 * Every account, admin identity (email, created, last sign-in) joined with its ArcRadar profile
 * (display name, role, active flag). Reading `auth.users` needs the service role: there is no other
 * way to see another person's email. The caller must already be authorized (`users:read`).
 */
export async function findUsers(): Promise<AdminUser[]> {
  const admin = createAdminClient();

  const identities: {
    id: string;
    email: string | null;
    created_at: string;
    last_sign_in_at: string | null;
  }[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: PAGE_SIZE });
    if (error) throw toApiError(error);
    identities.push(
      ...data.users.map((user) => ({
        id: user.id,
        email: user.email ?? null,
        created_at: user.created_at,
        last_sign_in_at: user.last_sign_in_at ?? null,
      })),
    );
    if (data.users.length < PAGE_SIZE) break;
  }

  const { data: profiles, error } = await admin
    .from("profiles")
    .select("id, display_name, role_name, is_active, approved_at");
  if (error) throw toApiError(error);
  const byId = new Map(profiles.map((row) => [row.id, row]));

  return identities.map((identity) => {
    const profile = byId.get(identity.id);
    return {
      id: identity.id,
      email: identity.email,
      display_name: profile?.display_name ?? null,
      role: profile && isRoleName(profile.role_name) ? profile.role_name : "viewer",
      is_active: profile?.is_active ?? false,
      pending: profile ? !profile.is_active && profile.approved_at === null : false,
      created_at: identity.created_at,
      last_sign_in_at: identity.last_sign_in_at,
    };
  });
}

export async function findProfileForAdmin(
  id: string,
): Promise<{ role_name: string; is_active: boolean; approved_at: string | null } | null> {
  const admin = createAdminClient();
  const { data, error } = await admin
    .from("profiles")
    .select("role_name, is_active, approved_at")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Active administrators, for the "do not lock everyone out" check. */
export async function countActiveAdmins(): Promise<number> {
  const admin = createAdminClient();
  const { count, error } = await admin
    .from("profiles")
    .select("id", { count: "exact", head: true })
    .eq("role_name", "admin")
    .eq("is_active", true);
  if (error) throw toApiError(error);
  return count ?? 0;
}

export async function updateProfileForAdmin(
  id: string,
  patch: { role_name?: RoleName; is_active?: boolean },
): Promise<void> {
  const admin = createAdminClient();
  const { error } = await admin.from("profiles").update(patch).eq("id", id);
  if (error) throw toApiError(error);
}
