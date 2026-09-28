import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateChecklistItemSchema } from "@/lib/investigations/schema";
import { removeChecklistItem, toggleChecklistItem } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

type Params = { id: string; itemId: string };

/**
 * PATCH /api/investigations/:id/checklist/:itemId  { done }
 * Checks or unchecks an item; the server records who and when. Needs investigations:write.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const { done } = await parseJsonBody(request, updateChecklistItemSchema);
    return ok(await toggleChecklistItem(auth, params.id, params.itemId, done, request));
  },
);

/** DELETE /api/investigations/:id/checklist/:itemId — needs investigations:write. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) =>
    ok(await removeChecklistItem(auth, params.id, params.itemId, request)),
);
