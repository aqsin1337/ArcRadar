import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { addAlertLinkSchema } from "@/lib/investigations/schema";
import { attachAlert } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/**
 * POST /api/investigations/:id/alerts  { alert_id } — attaches an alert (409 if it already is). A new or
 * acknowledged alert moves to `investigating`. Needs investigations:write.
 */
export const POST = protectedRoute<{ id: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const { alert_id } = await parseJsonBody(request, addAlertLinkSchema);
    return ok(await attachAlert(auth, params.id, alert_id, request), { status: 201 });
  },
);
