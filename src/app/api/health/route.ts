import { getPublicEnv, isSupabaseConfigured } from "@/lib/env/public";
import { fail, ok } from "@/lib/api/response";
import { logError } from "@/lib/log";

export const dynamic = "force-dynamic";

// 3s was tight for a cross-region call (a Vercel function and its Supabase project are rarely in
// the same region) and, worse, swallowed the real reason silently -- matches the deadline the
// intel providers use for their own live, cross-region lookups (LIVE_TIMEOUT_MS in
// src/lib/intel/service.ts), not an arbitrary bump.
const SUPABASE_HEALTH_TIMEOUT_MS = 8000;

type SupabaseStatus = "ok" | "unreachable" | "not_configured";

async function checkSupabase(): Promise<SupabaseStatus> {
  if (!isSupabaseConfigured()) return "not_configured";

  const env = getPublicEnv();
  try {
    const response = await fetch(`${env.NEXT_PUBLIC_SUPABASE_URL}/auth/v1/health`, {
      headers: { apikey: env.NEXT_PUBLIC_SUPABASE_ANON_KEY },
      cache: "no-store",
      signal: AbortSignal.timeout(SUPABASE_HEALTH_TIMEOUT_MS),
    });
    if (!response.ok) {
      logError("health.supabase_not_ok", new Error(`status ${response.status}`), {});
      return "unreachable";
    }
    return "ok";
  } catch (error) {
    // Never silent: this is the one place that would otherwise hide *why* a deployment reports
    // itself unhealthy, and "unreachable" alone was not enough to diagnose the first hosted
    // deployment (turned out to be too tight a timeout, found only via Vercel's function logs
    // after adding this).
    logError("health.supabase_check_failed", error, {});
    return "unreachable";
  }
}

/** Liveness plus a Supabase reachability check. Exposes no configuration values. */
export async function GET() {
  const supabase = await checkSupabase();
  const data = { app: "arcradar", status: supabase === "ok" ? "ok" : "degraded", supabase };

  return supabase === "ok"
    ? ok(data)
    : fail(503, "DEPENDENCY_UNAVAILABLE", "Supabase is not reachable or not configured.", data);
}
