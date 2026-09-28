import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getVulnerabilityStats } from "@/lib/vulnerabilities/service";

export const dynamic = "force-dynamic";

/** GET /api/vulnerabilities/stats — record counts per severity and how many are exploited. Needs vulnerabilities:read. */
export const GET = protectedRoute({ permissions: ["vulnerabilities:read"] }, async ({ auth }) =>
  ok(await getVulnerabilityStats(auth.supabase)),
);
