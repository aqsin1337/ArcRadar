import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getAlertStats } from "@/lib/alerts/service";

export const dynamic = "force-dynamic";

/** GET /api/alerts/stats — alerts per status (lifecycle order) and how many nobody has picked up. Needs alerts:read. */
export const GET = protectedRoute({ permissions: ["alerts:read"] }, async ({ auth }) =>
  ok(await getAlertStats(auth.supabase)),
);
