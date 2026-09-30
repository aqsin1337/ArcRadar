import "server-only";
import type { SupabaseClient, User } from "@supabase/supabase-js";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import { logError } from "@/lib/log";
import { isRoleName, permissionsForRole, type Permission } from "@/lib/rbac/permissions";
import type { Database } from "@/types/database";
import type { RoleName } from "@/types/domain";

export type AuthClient = SupabaseClient<Database>;

/** Everything a guarded handler needs to know about the caller. */
export type AuthContext = {
  supabase: AuthClient;
  user: { id: string; email: string | null };
  profile: { display_name: string | null; role: RoleName };
  permissions: ReadonlySet<Permission>;
};

/** What the API returns about the signed-in user (GET /api/auth/me, POST /api/auth/login). */
export type SessionInfo = {
  user: AuthContext["user"];
  profile: AuthContext["profile"];
  permissions: Permission[];
};

export function toSessionInfo(auth: AuthContext): SessionInfo {
  return { user: auth.user, profile: auth.profile, permissions: [...auth.permissions] };
}

/** AuthRetryableFetchError and network failures carry status 0/undefined; 5xx means GoTrue is down. */
export function isAuthServiceDown(error: { status?: number }) {
  return error.status === undefined || error.status === 0 || error.status >= 500;
}

/**
 * Why a signed-in person has no usable profile: still waiting for approval, or disabled. RLS hides an
 * inactive profile from its owner, so this asks a security-definer function that answers for the
 * caller only. Any failure to ask means "disabled" (fail closed).
 */
async function inactiveAccountError(supabase: AuthClient) {
  try {
    const { data } = await supabase.rpc("account_state");
    if (data === "pending") return apiErrors.accountPending();
  } catch {
    // fall through: treat as disabled
  }
  return apiErrors.accountDisabled();
}

/**
 * Loads the caller's profile and resolves their permissions for an already validated auth user.
 * RLS on `profiles` only shows the row of an active user, so a missing row means the account is
 * disabled (or has no profile) and gets no access.
 */
export async function buildAuthContext(supabase: AuthClient, user: User): Promise<AuthContext> {
  const { data, error } = await supabase
    .from("profiles")
    .select("display_name, role_name, is_active")
    .eq("id", user.id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data || !data.is_active) throw await inactiveAccountError(supabase);

  if (!isRoleName(data.role_name)) {
    // A role exists in the database that this build does not know: fail closed.
    logError("auth.unknown_role", new Error("Unknown role in profiles"), { user_id: user.id });
    throw apiErrors.forbidden();
  }

  return {
    supabase,
    user: { id: user.id, email: user.email ?? null },
    profile: { display_name: data.display_name, role: data.role_name },
    permissions: permissionsForRole(data.role_name),
  };
}

/**
 * Validates the session cookie against Supabase Auth (`getUser()` verifies the token with the auth
 * server, unlike reading the cookie) and returns the caller's context. Throws 401 without a valid
 * session, 403 for a disabled account, 503 when the auth backend is unreachable.
 */
export async function requireAuth(supabase: AuthClient): Promise<AuthContext> {
  const { data, error } = await supabase.auth.getUser();
  if (error) {
    if (isAuthServiceDown(error)) throw apiErrors.unavailable("Authentication is unavailable.");
    throw apiErrors.unauthenticated();
  }
  if (!data.user) throw apiErrors.unauthenticated();
  return buildAuthContext(supabase, data.user);
}

/** Throws 403 unless the caller holds every listed permission. */
export function assertPermissions(auth: AuthContext, required: readonly Permission[]) {
  if (!required.every((permission) => auth.permissions.has(permission))) {
    throw apiErrors.forbidden();
  }
}
