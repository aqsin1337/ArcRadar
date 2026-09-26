import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { globalSearch, searchQuerySchema } from "@/lib/search/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/search?q=<text>&limit=<1-10 per group>
 * Searches every record type the caller may read; results are grouped by type.
 */
export const GET = protectedRoute({}, async ({ request, auth }) => {
  const { q, limit } = parseQuery(request, searchQuerySchema);
  return ok(await globalSearch(auth, q, limit));
});
