import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import { createReportSchema, reportListQuerySchema } from "@/lib/reports/schema";
import { createReport, listReports } from "@/lib/reports/service";

export const dynamic = "force-dynamic";

/** GET /api/reports?type&page&page_size — newest first. Needs reports:read. */
export const GET = protectedRoute({ permissions: ["reports:read"] }, async ({ request, auth }) => {
  const query = parseQuery(request, reportListQuerySchema);
  return ok(await listReports(auth, query));
});

/**
 * POST /api/reports  { type, title?, ...fields the type needs }
 * Generates a report from the workspace's current data and stores the snapshot (needs
 * reports:write). A report never changes afterwards; generate a new one to refresh it.
 */
export const POST = protectedRoute(
  { permissions: ["reports:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createReportSchema);
    return ok(await createReport(auth, input, request), { status: 201 });
  },
);
