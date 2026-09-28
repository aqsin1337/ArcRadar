import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { generateAlertAnalysis, listAlertAnalyses } from "@/lib/ai/service";
import { userSubject } from "@/lib/rate-limit/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

const bodySchema = z.strictObject({
  kind: z.enum([
    "threat_summary",
    "attack_vector",
    "severity_validation",
    "response_actions",
    "false_positive_score",
  ]),
});

/**
 * GET /api/alerts/:id/ai — the latest AI analysis per kind for this alert, plus a short history.
 * Needs alerts:read: anyone who can see the alert sees analyses already generated for it.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["alerts:read"] },
  async ({ auth, params }) => ok(await listAlertAnalyses(auth.supabase, params.id)),
);

/**
 * POST /api/alerts/:id/ai  { kind }
 * Asks the active AI provider for one kind of analysis on this alert, validates and stores the
 * answer, and audits the call. Needs ai:use and alerts:read. 503 when no provider is configured
 * and ready; 429 when the provider's own rate limit was hit, or when this analyst has asked too
 * many times this hour (`aiByUser`, a real metered cost per call).
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["ai:use", "alerts:read"],
    rateLimit: { routeClass: "aiByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) => {
    const { kind } = await parseJsonBody(request, bodySchema);
    return ok(await generateAlertAnalysis(auth, params.id, kind, request), { status: 201 });
  },
);
