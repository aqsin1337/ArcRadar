import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { setIndicatorLinksSchema } from "@/lib/indicators/schema";
import { setIndicatorLinks } from "@/lib/indicators/service";

export const dynamic = "force-dynamic";

/**
 * PUT /api/indicators/:id/links  { actor_ids?, campaign_ids?, malware_ids? } — needs indicators:write.
 * Sets which threat actors, campaigns and malware families the indicator is linked to. A list replaces
 * that whole set (an empty list clears it); a list left out is kept. Every id must exist, or nothing
 * changes (422). Returns the indicator.
 */
export const PUT = protectedRoute<{ id: string }>(
  { permissions: ["indicators:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, setIndicatorLinksSchema);
    return ok(await setIndicatorLinks(auth, params.id, input, request));
  },
);
