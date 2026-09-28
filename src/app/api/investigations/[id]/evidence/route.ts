import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { evidenceSchema } from "@/lib/investigations/schema";
import { addEvidence } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/**
 * POST /api/investigations/:id/evidence  { title, location, description? } — adds an evidence reference
 * (a link, a file hash, a ticket number: a reference, not an upload). Needs investigations:write.
 */
export const POST = protectedRoute<{ id: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, evidenceSchema);
    return ok(await addEvidence(auth, params.id, input, request), { status: 201 });
  },
);
