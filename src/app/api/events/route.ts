import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { eventListQuerySchema } from "@/lib/telemetry/schema";
import { listEvents } from "@/lib/telemetry/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/events?source&severity&origin&asset&sort&order&page&page_size — security events, newest
 * first: each with its asset and the alert raised from it (`alert_id`). `sort`: `occurred_at` (default),
 * `created_at` (when it was received), `severity`. The raw alert (`payload`) is on the alert page, not
 * here. Read-only. Needs events:read.
 */
export const GET = protectedRoute({ permissions: ["events:read"] }, async ({ request, auth }) => {
  const query = parseQuery(request, eventListQuerySchema);
  return ok(await listEvents(auth.supabase, query));
});
