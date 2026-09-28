import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getInvestigationStats } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** GET /api/investigations/stats — investigations per status, in lifecycle order. Needs investigations:read. */
export const GET = protectedRoute({ permissions: ["investigations:read"] }, async ({ auth }) =>
  ok(await getInvestigationStats(auth.supabase)),
);
