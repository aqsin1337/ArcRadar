import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { removeRelationship } from "@/lib/indicators/service";

export const dynamic = "force-dynamic";

/** DELETE /api/indicators/:id/relationships/:relationshipId — needs indicators:write. */
export const DELETE = protectedRoute<{ id: string; relationshipId: string }>(
  { permissions: ["indicators:write"] },
  async ({ request, auth, params }) => {
    await removeRelationship(auth, params.id, params.relationshipId, request);
    return ok({ deleted: true });
  },
);
