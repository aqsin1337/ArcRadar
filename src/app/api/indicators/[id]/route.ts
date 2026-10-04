import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateIndicatorSchema } from "@/lib/indicators/schema";
import { deleteIndicator, getIndicator, updateIndicator } from "@/lib/indicators/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/indicators/:id — the indicator with tags, linked entities and relationships. */
export const GET = protectedRoute<Params>(
  { permissions: ["indicators:read"] },
  async ({ auth, params }) => ok(await getIndicator(auth.supabase, params.id)),
);

/**
 * PATCH /api/indicators/:id  { severity?, verdict?, status?, confidence?, source?, description?,
 * first_seen?, last_seen?, tags? } — needs indicators:write. Type and value cannot change.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["indicators:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateIndicatorSchema);
    return ok(await updateIndicator(auth, params.id, input, request));
  },
);

/** DELETE /api/indicators/:id — needs indicators:delete (admins). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["indicators:delete"] },
  async ({ request, auth, params }) => {
    await deleteIndicator(auth, params.id, request);
    return ok({ deleted: true });
  },
);
