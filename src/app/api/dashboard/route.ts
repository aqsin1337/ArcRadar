import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { dashboardQuerySchema } from "@/lib/dashboard/schema";
import { getDashboardData } from "@/lib/dashboard/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/dashboard?days&severity — the Overview page's data (counts, distributions, the activity
 * series, top threat actors and malicious indicators, and recent alerts/investigations/indicators).
 * Available to every signed-in role; the counts are the workspace's real totals.
 */
export const GET = protectedRoute({}, async ({ request, auth }) => {
  const query = parseQuery(request, dashboardQuerySchema);
  return ok(await getDashboardData(auth, query));
});
