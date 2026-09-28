import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateResponseActionLogSchema } from "@/lib/response-actions/schema";
import { removeResponseActionLog, updateResponseActionLog } from "@/lib/response-actions/service";

export const dynamic = "force-dynamic";

type Params = { id: string; logId: string };

/**
 * PATCH /api/alerts/:id/response-actions/:logId  { status, notes? }
 * Moves a recommendation forward (recommended -> acknowledged -> completed/skipped, never
 * backwards); `409` for a move the lifecycle does not allow. Needs alerts:write.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["alerts:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateResponseActionLogSchema);
    return ok(await updateResponseActionLog(auth, params.id, params.logId, input, request));
  },
);

/** DELETE /api/alerts/:id/response-actions/:logId — removes a mistaken recommendation. Needs alerts:write. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["alerts:write"] },
  async ({ request, auth, params }) =>
    ok(await removeResponseActionLog(auth, params.id, params.logId, request)),
);
