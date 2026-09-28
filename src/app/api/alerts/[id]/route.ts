import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateAlertSchema } from "@/lib/alerts/schema";
import { deleteAlert, getAlert, updateAlert } from "@/lib/alerts/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/alerts/:id — the alert with its indicator, event, assignee and investigations. */
export const GET = protectedRoute<Params>(
  { permissions: ["alerts:read"] },
  async ({ auth, params }) => ok(await getAlert(auth.supabase, params.id)),
);

/**
 * PATCH /api/alerts/:id  { status?, assigned_to? } — needs alerts:write.
 * `status` follows the lifecycle (new, acknowledged, investigating, resolved, false_positive; a closed
 * alert can only go back to investigating): anything else is 409, and so is a change made by someone
 * else in the meantime. `assigned_to` is a user id, `me` or null.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["alerts:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateAlertSchema);
    return ok(await updateAlert(auth, params.id, input, request));
  },
);

/** DELETE /api/alerts/:id — needs alerts:delete (administrators). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["alerts:delete"] },
  async ({ request, auth, params }) => {
    await deleteAlert(auth, params.id, request);
    return ok({ deleted: true });
  },
);
