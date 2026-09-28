import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import {
  createInvestigationSchema,
  investigationListQuerySchema,
} from "@/lib/investigations/schema";
import { createInvestigation, listInvestigations } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/investigations?q&status&priority&analyst&tag&origin&sort&order&page&page_size
 * Text search (all terms must match the title, description, a tag or the value of an attached
 * indicator), filters (`analyst` is `me`, `none` or a user id), sorting and pagination. Needs investigations:read.
 */
export const GET = protectedRoute(
  { permissions: ["investigations:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, investigationListQuerySchema);
    return ok(await listInvestigations(auth, query));
  },
);

/**
 * POST /api/investigations  { title, description?, priority?, analyst_id?, tags?, indicator_ids?, alert_ids? }
 * Opens an investigation (needs investigations:write): always `open` and local, assigned to the caller
 * unless `analyst_id` says otherwise. Attached alerts move to `investigating`.
 */
export const POST = protectedRoute(
  { permissions: ["investigations:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createInvestigationSchema);
    return ok(await createInvestigation(auth, input, request), { status: 201 });
  },
);
