import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { createResponseActionSchema } from "@/lib/response-actions/schema";
import { createResponseAction, listResponseActions } from "@/lib/response-actions/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/response-actions — the catalog of reusable response actions. Needs alerts:read (the
 * catalog is read wherever a response action can be recommended or attached).
 */
export const GET = protectedRoute({ permissions: ["alerts:read"] }, async ({ auth }) =>
  ok(await listResponseActions(auth.supabase)),
);

/**
 * POST /api/response-actions  { title, description?, category? }
 * Adds a catalog entry; always local. Needs investigations:write (curated the same way an
 * investigation itself is, not admin-only).
 */
export const POST = protectedRoute(
  { permissions: ["investigations:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createResponseActionSchema);
    return ok(await createResponseAction(auth, input, request), { status: 201 });
  },
);
