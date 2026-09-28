import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateInvestigationSchema } from "@/lib/investigations/schema";
import {
  deleteInvestigation,
  getInvestigation,
  updateInvestigation,
} from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/investigations/:id — the investigation with its indicators, alerts, notes, evidence and timeline. */
export const GET = protectedRoute<Params>(
  { permissions: ["investigations:read"] },
  async ({ auth, params }) => ok(await getInvestigation(auth.supabase, params.id)),
);

/**
 * PATCH /api/investigations/:id  { title?, description?, status?, priority?, analyst_id?, tags? }
 * Needs investigations:write. A change of status, priority or analyst is recorded in the history;
 * closing sets `closed_at`.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateInvestigationSchema);
    return ok(await updateInvestigation(auth, params.id, input, request));
  },
);

/** DELETE /api/investigations/:id — needs investigations:delete (administrators). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["investigations:delete"] },
  async ({ request, auth, params }) => {
    await deleteInvestigation(auth, params.id, request);
    return ok({ deleted: true });
  },
);
