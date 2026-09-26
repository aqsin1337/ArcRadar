import { getPublicEnv, isSupabaseConfigured } from "@/lib/env/public";
import { fail, ok } from "@/lib/api/response";

export const dynamic = "force-dynamic";

type SupabaseStatus = "ok" | "unreachable" | "not_configured";

async function checkSupabase(): Promise<SupabaseStatus> {
  if (!isSupabaseConfigured()) return "not_configured";

  const env = getPublicEnv();
  try {
    const response = await fetch(`${env.NEXT_PUBLIC_SUPABASE_URL}/auth/v1/health`, {
      headers: { apikey: env.NEXT_PUBLIC_SUPABASE_ANON_KEY },
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    return response.ok ? "ok" : "unreachable";
  } catch {
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
