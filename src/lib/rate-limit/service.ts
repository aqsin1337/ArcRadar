import "server-only";
import { ApiError, apiErrors } from "@/lib/api/errors";
import { getClientIp } from "@/lib/audit/request-meta";
import { logError } from "@/lib/log";
import { createAdminClient } from "@/lib/supabase/admin";
import type { RateLimitClass, RateLimitRule } from "./constants";
import { RATE_LIMITS } from "./constants";

/** Builds a bucket key that starts with the route class, so different endpoints never collide. */
function bucketKey(routeClass: RateLimitClass, subject: string): string {
  return `${routeClass}:${subject}`;
}

/** Keys by the caller's IP address (for routes with no session yet, such as login). */
export function ipSubject(request: { headers: Headers }): string {
  return getClientIp(request.headers) ?? "unknown";
}

/** Keys by the signed-in caller (routes wrapped in `protectedRoute` always have one by the time
 * the rate-limit check runs, but the type is optional to match the shared route context). */
export function userSubject(auth: { user: { id: string } } | undefined): string {
  return auth?.user.id ?? "anonymous";
}

/**
 * Checks and consumes one request against a rule's shared, database-backed counter (Vercel
 * functions keep no memory between invocations, and decision 1 rules out a second store, so
 * Postgres is the only place a counter can live). Throws `apiErrors.rateLimited()` with
 * `Retry-After` once the bucket is over its limit.
 *
 * Fails open on an infrastructure problem (the same posture `writeAuditLog` takes): a broken
 * limiter must never turn every request into a 500, or into an outage indistinguishable from the
 * abuse it exists to stop.
 */
export async function enforceRateLimit(routeClass: RateLimitClass, subject: string): Promise<void> {
  const rule: RateLimitRule = RATE_LIMITS[routeClass];
  const key = bucketKey(routeClass, subject);
  try {
    const { data, error } = await createAdminClient()
      .rpc("check_rate_limit", {
        p_key: key,
        p_limit: rule.limit,
        p_window_seconds: rule.windowSeconds,
      })
      .single();
    if (error) throw error;
    if (!data.allowed) throw apiErrors.rateLimited(data.retry_after_seconds ?? rule.windowSeconds);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    logError("rate_limit.check_failed", error, { route_class: routeClass });
  }
}
