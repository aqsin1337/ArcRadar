import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { attachResponseActionSchema } from "@/lib/response-actions/schema";
import { attachResponseAction, listAlertResponseActions } from "@/lib/response-actions/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/**
 * GET /api/alerts/:id/response-actions — every recommendation/execution logged for this alert
 * (AI-seeded or attached by hand), oldest first. Needs alerts:read.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["alerts:read"] },
  async ({ auth, params }) => ok(await listAlertResponseActions(auth.supabase, params.id)),
);

/**
 * POST /api/alerts/:id/response-actions  { action_id }
 * An analyst manually recommends an existing catalog action for this alert (status starts
 * `recommended`, same as an AI suggestion). Needs alerts:write.
 */
export const POST = protectedRoute<Params>(
  { permissions: ["alerts:write"] },
  async ({ request, auth, params }) => {
    const { action_id } = await parseJsonBody(request, attachResponseActionSchema);
    return ok(await attachResponseAction(auth, params.id, action_id, request), { status: 201 });
  },
);
