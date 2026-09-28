import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { deleteReport, getReport } from "@/lib/reports/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/reports/:id — the generated snapshot. Needs reports:read. */
export const GET = protectedRoute<Params>(
  { permissions: ["reports:read"] },
  async ({ auth, params }) => ok(await getReport(auth, params.id)),
);

/** DELETE /api/reports/:id — needs reports:write (any holder, like the other write actions). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["reports:write"] },
  async ({ request, auth, params }) => {
    await deleteReport(auth, params.id, request);
    return ok({ deleted: true });
  },
);
