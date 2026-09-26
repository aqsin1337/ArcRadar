import "server-only";
import type { AuthError } from "@supabase/supabase-js";
import { ApiError, apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import { getPublicEnv } from "@/lib/env/public";
import { logError, logWarn } from "@/lib/log";
import type { LoginInput, SignupInput } from "@/lib/validation/auth";
import {
  buildAuthContext,
  isAuthServiceDown,
  toSessionInfo,
  type AuthClient,
  type AuthContext,
  type SessionInfo,
} from "./context";

type RequestLike = { headers: Headers };

function authUrl(path: string) {
  return new URL(path, getPublicEnv().NEXT_PUBLIC_APP_URL).toString();
}

function isRateLimited(error: AuthError) {
  return error.status === 429 || error.code === "over_request_rate_limit";
}

/** Failures that say nothing about the caller's input: back off or report the outage. */
function transientFailure(error: AuthError): ApiError | null {
  if (isRateLimited(error)) return apiErrors.rateLimited();
  if (isAuthServiceDown(error)) return apiErrors.unavailable("Authentication is unavailable.");
  return null;
}

async function signOutLocal(supabase: AuthClient) {
  const { error } = await supabase.auth.signOut({ scope: "local" });
  if (error) logError("auth.sign_out_failed", error);
}

async function loginFailure(error: AuthError | null, email: string, request: RequestLike) {
  if (error) {
    const transient = transientFailure(error);
    if (transient) return transient;
  }

  const reason = error?.code ?? "unknown";
  await writeAuditLog(
    { action: "auth.login_failed", entityType: "user", metadata: { email, reason } },
    request,
  );

  if (reason === "email_not_confirmed") return apiErrors.emailNotConfirmed();
  if (reason === "user_banned") return apiErrors.accountDisabled();
  // Wrong password and unknown email look the same to the caller (no account enumeration).
  return apiErrors.invalidCredentials();
}

/** Signs in with email + password; the session cookies are set by the server Supabase client. */
export async function login(
  supabase: AuthClient,
  input: LoginInput,
  request: RequestLike,
): Promise<SessionInfo> {
  const { data, error } = await supabase.auth.signInWithPassword({
    email: input.email,
    password: input.password,
  });
  if (error || !data.user) throw await loginFailure(error, input.email, request);

  let auth: AuthContext;
  try {
    auth = await buildAuthContext(supabase, data.user);
  } catch (failure) {
    // Valid credentials but no usable account (disabled, no profile): do not leave a session behind.
    await signOutLocal(supabase);
    if (failure instanceof ApiError && failure.code === "ACCOUNT_DISABLED") {
      await writeAuditLog(
        {
          action: "auth.login_failed",
          userId: data.user.id,
          entityType: "user",
          entityId: data.user.id,
          metadata: { reason: "account_disabled" },
        },
        request,
      );
    }
    throw failure;
  }

  await writeAuditLog(
    { action: "auth.login", userId: auth.user.id, entityType: "user", entityId: auth.user.id },
    request,
  );
  return toSessionInfo(auth);
}

/** Ends the current session. Idempotent: signing out without a session succeeds. */
export async function logout(supabase: AuthClient, request: RequestLike): Promise<void> {
  const { data } = await supabase.auth.getUser();
  const { error } = await supabase.auth.signOut({ scope: "local" });
  if (error) throw apiErrors.unavailable("Sign-out could not be completed.");

  if (data.user) {
    await writeAuditLog(
      {
        action: "auth.logout",
        userId: data.user.id,
        entityType: "user",
        entityId: data.user.id,
      },
      request,
    );
  }
}

/**
 * Registers a new account. New users are always `viewer` (the role is set by a database trigger and
 * never read from the request). The outcome is identical whether or not the email is already
 * registered, and the caller is never signed in by registering, so the endpoint cannot be used to
 * discover accounts. Turn sign-ups off entirely in the Supabase dashboard if the deployment is
 * invite-only.
 */
export async function signup(
  supabase: AuthClient,
  input: SignupInput,
  request: RequestLike,
): Promise<void> {
  const { data, error } = await supabase.auth.signUp({
    email: input.email,
    password: input.password,
    options: {
      data: input.display_name ? { display_name: input.display_name } : {},
      emailRedirectTo: authUrl("/auth/callback"),
    },
  });

  if (error) {
    const transient = transientFailure(error);
    if (transient) throw transient;
    if (error.code === "user_already_exists" || error.code === "email_exists") return;
    if (error.code === "weak_password") {
      throw apiErrors.validation(undefined, "The password does not meet the requirements.");
    }
    if (error.code === "signup_disabled") {
      throw new ApiError(403, "FORBIDDEN", "Sign-ups are disabled.");
    }
    logError("auth.signup_failed", error, { reason: error.code });
    throw apiErrors.badRequest("The account could not be created.");
  }

  if (data.session) await signOutLocal(supabase);

  // An obfuscated duplicate (email confirmation on) comes back with an empty identities list.
  if (data.user && (data.user.identities?.length ?? 0) > 0) {
    await writeAuditLog(
      {
        action: "auth.signup",
        userId: data.user.id,
        entityType: "user",
        entityId: data.user.id,
        metadata: { email: input.email },
      },
      request,
    );
  }
}

/** Sends a recovery email. Always succeeds for the caller, whether or not the email is registered. */
export async function requestPasswordReset(
  supabase: AuthClient,
  email: string,
  request: RequestLike,
): Promise<void> {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: authUrl("/auth/callback?next=/reset-password"),
  });

  if (error) {
    const transient = transientFailure(error);
    if (transient) throw transient;
    logWarn("auth.password_reset_request_failed", { reason: error.code });
  }

  await writeAuditLog(
    { action: "auth.password_reset_requested", entityType: "user", metadata: { email } },
    request,
  );
}

/** Sets a new password for the current session and signs out every other session. */
export async function updatePassword(
  auth: AuthContext,
  password: string,
  request: RequestLike,
): Promise<void> {
  const { error } = await auth.supabase.auth.updateUser({ password });
  if (error) {
    const transient = transientFailure(error);
    if (transient) throw transient;
    if (error.code === "same_password") {
      throw apiErrors.validation(undefined, "The new password must differ from the current one.");
    }
    if (error.code === "weak_password") {
      throw apiErrors.validation(undefined, "The password does not meet the requirements.");
    }
    if (error.code === "reauthentication_needed" || error.code === "reauth_nonce_missing") {
      throw apiErrors.forbidden("Sign in again before changing the password.");
    }
    logError("auth.update_password_failed", error, { reason: error.code });
    throw apiErrors.badRequest("The password could not be updated.");
  }

  const { error: revokeError } = await auth.supabase.auth.signOut({ scope: "others" });
  if (revokeError) logError("auth.revoke_other_sessions_failed", revokeError);

  await writeAuditLog(
    {
      action: "auth.password_changed",
      userId: auth.user.id,
      entityType: "user",
      entityId: auth.user.id,
    },
    request,
  );
}
