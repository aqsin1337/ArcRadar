import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { createWazuhRuleSchema } from "@/lib/wazuh-rules/schema";
import { createWazuhRule, listWazuhRules } from "@/lib/wazuh-rules/service";

export const dynamic = "force-dynamic";

/** GET /api/wazuh-rules — every rule with its generated XML and trigger counts. Needs rules:manage. */
export const GET = protectedRoute({ permissions: ["rules:manage"] }, async ({ auth }) =>
  ok(await listWazuhRules(auth.supabase)),
);

/**
 * POST /api/wazuh-rules  { id?, name, description?, level, parent_kind, parent_value, conditions,
 * mitre_ids? } — a hand-written rule, always a draft. Needs rules:manage. Without an id the next free
 * one is used.
 */
export const POST = protectedRoute({ permissions: ["rules:manage"] }, async ({ request, auth }) => {
  const input = await parseJsonBody(request, createWazuhRuleSchema);
  return ok(await createWazuhRule(auth, input, request), { status: 201 });
});
