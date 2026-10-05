import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { createDetectionRuleSchema } from "@/lib/detection-rules/schema";
import { createDetectionRule, listDetectionRules } from "@/lib/detection-rules/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/detection-rules — the rule catalog. Needs alerts:read (an analyst should be able to see
 * why a rule raised an alert's severity, the same reasoning as the response-action catalog).
 */
export const GET = protectedRoute({ permissions: ["alerts:read"] }, async ({ auth }) =>
  ok(await listDetectionRules(auth.supabase)),
);

/**
 * POST /api/detection-rules  { id, name, description?, conditions, severity?, priority?, enabled? }
 * Needs rules:manage (admin only). Always local.
 */
export const POST = protectedRoute({ permissions: ["rules:manage"] }, async ({ request, auth }) => {
  const input = await parseJsonBody(request, createDetectionRuleSchema);
  return ok(await createDetectionRule(auth, input, request), { status: 201 });
});
