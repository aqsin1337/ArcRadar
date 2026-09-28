import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateResponseActionSchema } from "@/lib/response-actions/schema";
import { deleteResponseAction, updateResponseAction } from "@/lib/response-actions/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** PATCH /api/response-actions/:id  { title?, description?, category? } — needs investigations:write. */
export const PATCH = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateResponseActionSchema);
    return ok(await updateResponseAction(auth, params.id, input, request));
  },
);

/**
 * DELETE /api/response-actions/:id — needs investigations:write. `409` if an alert has already
 * recommended or logged this action (its history is kept, not silently orphaned).
 */
export const DELETE = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    await deleteResponseAction(auth, params.id, request);
    return ok({ deleted: true });
  },
);
