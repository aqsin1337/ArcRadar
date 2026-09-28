import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { addIndicatorLinkSchema } from "@/lib/investigations/schema";
import { attachIndicator } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** POST /api/investigations/:id/indicators  { indicator_id } — attaches an indicator (409 if it already is). Needs investigations:write. */
export const POST = protectedRoute<{ id: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const { indicator_id } = await parseJsonBody(request, addIndicatorLinkSchema);
    return ok(await attachIndicator(auth, params.id, indicator_id, request), { status: 201 });
  },
);
