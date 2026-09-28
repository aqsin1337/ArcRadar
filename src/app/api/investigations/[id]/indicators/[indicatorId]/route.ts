import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { detachIndicator } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** DELETE /api/investigations/:id/indicators/:indicatorId — detaches an indicator. Needs investigations:write. */
export const DELETE = protectedRoute<{ id: string; indicatorId: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) =>
    ok(await detachIndicator(auth, params.id, params.indicatorId, request)),
);
