import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { createChecklistItemSchema } from "@/lib/investigations/schema";
import { addChecklistItem, getChecklist } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/investigations/:id/checklist — every item, oldest first. Needs investigations:read. */
export const GET = protectedRoute<Params>(
  { permissions: ["investigations:read"] },
  async ({ auth, params }) => ok(await getChecklist(auth.supabase, params.id)),
);

/**
 * POST /api/investigations/:id/checklist  { text }
 * Adds an item by hand (an AI checklist suggestion adds its own, through the AI analysis endpoint).
 * Needs investigations:write.
 */
export const POST = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, createChecklistItemSchema);
    return ok(await addChecklistItem(auth, params.id, input, request), { status: 201 });
  },
);
