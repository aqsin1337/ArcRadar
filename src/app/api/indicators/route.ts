import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import { createIndicatorSchema, indicatorListQuerySchema } from "@/lib/indicators/schema";
import { createIndicator, listIndicators } from "@/lib/indicators/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/indicators?q&type&status&verdict&severity&origin&tag&sort&order&page&page_size
 * Text search (all terms must match value, description, source or a tag), filters, sorting and
 * pagination. Needs indicators:read.
 */
export const GET = protectedRoute(
  { permissions: ["indicators:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, indicatorListQuerySchema);
    return ok(await listIndicators(auth.supabase, query));
  },
);

/**
 * POST /api/indicators  { type, value, severity?, verdict?, status?, confidence?, source?,
 * description?, first_seen?, last_seen?, tags? }
 * Creates a local indicator (needs indicators:write). 409 with `details.existing_id` if it exists.
 */
export const POST = protectedRoute(
  { permissions: ["indicators:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createIndicatorSchema);
    return ok(await createIndicator(auth, input, request), { status: 201 });
  },
);
