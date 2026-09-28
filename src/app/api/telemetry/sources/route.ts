import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getSourceCards } from "@/lib/telemetry/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/telemetry/sources — every telemetry source with its status and when something last arrived:
 * the connectors ArcRadar can receive from (always listed), any other source that has delivered, and the
 * demo feeds. `status` is `receiving` (something arrived in the last 15 minutes), `quiet`, `never` or `demo`;
 * ArcRadar sees only what arrives, so it never claims a sensor is "connected". Needs events:read.
 */
export const GET = protectedRoute({ permissions: ["events:read"] }, async ({ auth }) =>
  ok(await getSourceCards(auth.supabase)),
);
