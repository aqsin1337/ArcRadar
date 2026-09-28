import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { addRelationshipSchema } from "@/lib/indicators/schema";
import { addRelationship } from "@/lib/indicators/service";

export const dynamic = "force-dynamic";

/**
 * POST /api/indicators/:id/relationships  { target_id, relationship } — needs indicators:write.
 * Relates this indicator (the source) to another one: `relationship` is one of resolves_to,
 * communicates_with, downloads, hosted_on, related_to. The same pair and kind twice is 409, an
 * indicator related to itself is 422. Returns the indicator.
 */
export const POST = protectedRoute<{ id: string }>(
  { permissions: ["indicators:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, addRelationshipSchema);
    return ok(await addRelationship(auth, params.id, input, request), { status: 201 });
  },
);
