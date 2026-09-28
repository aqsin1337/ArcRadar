import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { detachAlert } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** DELETE /api/investigations/:id/alerts/:alertId — detaches an alert (its status is left as it is). Needs investigations:write. */
export const DELETE = protectedRoute<{ id: string; alertId: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) =>
    ok(await detachAlert(auth, params.id, params.alertId, request)),
);
