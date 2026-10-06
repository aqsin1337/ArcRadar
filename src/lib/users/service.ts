import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import { isRoleName } from "@/lib/rbac/permissions";
import {
  countActiveAdmins,
  createAccountForAdmin,
  deleteAccountForAdmin,
  findProfileForAdmin,
  findUsers,
  updateProfileForAdmin,
} from "./repository";
import { userIdSchema, type CreateUserInput, type UpdateUserInput } from "./schema";
import type { AdminUser } from "./types";

type RequestLike = { headers: Headers };

export const isUserId = (id: string) => userIdSchema.safeParse(id).success;

export function listUsers(): Promise<AdminUser[]> {
  return findUsers();
}

/**
 * An administrator makes an account for a teammate: the sign-in exists at once (no confirmation
 * mail), already approved, with the role the administrator chose. If giving it the role fails, the
 * half-made sign-in is removed again, so no account is ever left that nobody approved. The password
 * is never logged or audited; the administrator passes it on and the person changes it on Profile.
 */
export async function createUser(
  auth: AuthContext,
  input: CreateUserInput,
  request: RequestLike,
): Promise<AdminUser> {
  const account = await createAccountForAdmin({
    email: input.email,
    password: input.password,
    display_name: input.display_name,
  });

  try {
    await updateProfileForAdmin(account.id, { role_name: input.role_name, is_active: true });
  } catch (error) {
    await deleteAccountForAdmin(account.id);
    throw error;
  }

  await writeAuditLog(
    {
      action: "user.created",
      userId: auth.user.id,
      entityType: "profile",
      entityId: account.id,
      metadata: { role: input.role_name },
    },
    request,
  );

  return {
    id: account.id,
    email: input.email,
    display_name: input.display_name,
    role: input.role_name,
    is_active: true,
    pending: false,
    created_at: account.created_at,
    last_sign_in_at: null,
  };
}

/**
 * Changes a person's role or active status. Never lets an administrator act on their own account
 * here (avoids an accidental self-lockout) and never leaves the workspace with zero active
 * administrators (there is no separate "root" account to recover with).
 */
export async function updateUser(
  auth: AuthContext,
  id: string,
  input: UpdateUserInput,
  request: RequestLike,
): Promise<void> {
  if (!isUserId(id)) throw apiErrors.notFound("Account not found.");
  if (id === auth.user.id) {
    throw apiErrors.conflict("You cannot change your own role or active status here.");
  }

  const current = await findProfileForAdmin(id);
  if (!current || !isRoleName(current.role_name)) throw apiErrors.notFound("Account not found.");

  const nextRole = input.role_name ?? current.role_name;
  const nextActive = input.is_active ?? current.is_active;
  const wasActiveAdmin = current.role_name === "admin" && current.is_active;
  const staysActiveAdmin = nextRole === "admin" && nextActive;
  if (wasActiveAdmin && !staysActiveAdmin && (await countActiveAdmins()) <= 1) {
    throw apiErrors.conflict("This is the only active administrator; leave at least one.");
  }

  await updateProfileForAdmin(id, {
    role_name: input.role_name,
    is_active: input.is_active,
  });

  if (input.role_name !== undefined && input.role_name !== current.role_name) {
    await writeAuditLog(
      {
        action: "user.role_changed",
        userId: auth.user.id,
        entityType: "profile",
        entityId: id,
        metadata: { from: current.role_name, to: input.role_name },
      },
      request,
    );
  }
  if (input.is_active !== undefined && input.is_active !== current.is_active) {
    const approval = input.is_active && current.approved_at === null;
    await writeAuditLog(
      {
        action: approval
          ? "user.approved"
          : input.is_active
            ? "user.activated"
            : "user.deactivated",
        userId: auth.user.id,
        entityType: "profile",
        entityId: id,
        metadata: approval ? { role: nextRole } : {},
      },
      request,
    );
  }
}
