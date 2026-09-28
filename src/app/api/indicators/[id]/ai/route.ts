import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { generateIndicatorAnalysis, listSubjectAnalyses } from "@/lib/ai/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

const bodySchema = z.strictObject({ kind: z.literal("verdict_recommendation") });

/**
 * GET /api/indicators/:id/ai — the latest AI analysis per kind for this indicator, plus a short
 * history. Needs indicators:read.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["indicators:read"] },
  async ({ auth, params }) => ok(await listSubjectAnalyses(auth.supabase, "indicator", params.id)),
);

/**
 * POST /api/indicators/:id/ai  { kind }
 * Asks the active AI provider for one kind of analysis on this indicator (in Phase 9, only
 * `verdict_recommendation`), validates and stores the answer, and audits the call. No side effect:
 * applying a recommended verdict is a normal, audited `PATCH /api/indicators/:id` the analyst makes
 * themselves. Needs ai:use and indicators:read. 503 when no provider is configured and ready; 429
 * when the provider's own rate limit was hit.
 */
export const POST = protectedRoute<Params>(
  { permissions: ["ai:use", "indicators:read"] },
  async ({ request, auth, params }) => {
    const { kind } = await parseJsonBody(request, bodySchema);
    return ok(await generateIndicatorAnalysis(auth, params.id, kind, request), { status: 201 });
  },
);
