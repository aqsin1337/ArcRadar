import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getIntegrations } from "@/lib/integrations/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/integrations — every provider ArcRadar knows, whether it is configured (a server-side
 * key is set) and whether an administrator has enabled it. Needs integrations:read.
 */
export const GET = protectedRoute({ permissions: ["integrations:read"] }, async ({ auth }) =>
  ok(await getIntegrations(auth.supabase)),
);
