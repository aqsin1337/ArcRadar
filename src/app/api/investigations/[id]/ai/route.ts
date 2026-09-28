import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { generateInvestigationAnalysis, listSubjectAnalyses } from "@/lib/ai/service";
import { userSubject } from "@/lib/rate-limit/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

const bodySchema = z.strictObject({ kind: z.literal("investigation_checklist") });

/**
 * GET /api/investigations/:id/ai — the latest AI analysis per kind for this investigation, plus a
 * short history. Needs investigations:read.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["investigations:read"] },
  async ({ auth, params }) =>
    ok(await listSubjectAnalyses(auth.supabase, "investigation", params.id)),
);

/**
 * POST /api/investigations/:id/ai  { kind }
 * Asks the active AI provider for one kind of analysis on this investigation (in Phase 9, only
 * `investigation_checklist`), validates and stores the answer, and audits the call. A
 * `investigation_checklist` answer also seeds trackable checklist items. Needs ai:use and
 * investigations:read. 503 when no provider is configured and ready; 429 when the provider's own
 * rate limit was hit, or when this analyst has asked too many times this hour (`aiByUser`).
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["ai:use", "investigations:read"],
    rateLimit: { routeClass: "aiByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) => {
    const { kind } = await parseJsonBody(request, bodySchema);
    return ok(await generateInvestigationAnalysis(auth, params.id, kind, request), { status: 201 });
  },
);
