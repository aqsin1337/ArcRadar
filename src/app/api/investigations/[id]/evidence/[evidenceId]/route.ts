import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { removeEvidence } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** DELETE /api/investigations/:id/evidence/:evidenceId — removes an evidence reference. Needs investigations:write. */
export const DELETE = protectedRoute<{ id: string; evidenceId: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) =>
    ok(await removeEvidence(auth, params.id, params.evidenceId, request)),
);
