import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { userSubject } from "@/lib/rate-limit/service";
import { generateWazuhRuleSchema } from "@/lib/wazuh-rules/schema";
import { generateWazuhRule } from "@/lib/wazuh-rules/service";

export const dynamic = "force-dynamic";

/**
 * POST /api/wazuh-rules/generate  { prompt } — the active AI provider drafts a rule from a
 * plain-language description. The draft is validated like a hand-written rule and stored as a
 * draft; nothing is pushed. Needs rules:manage and ai:use. 503 when no provider is ready.
 */
export const POST = protectedRoute(
  {
    permissions: ["rules:manage", "ai:use"],
    rateLimit: { routeClass: "wazuhRuleGenerateByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth }) => {
    const { prompt } = await parseJsonBody(request, generateWazuhRuleSchema);
    return ok(await generateWazuhRule(auth, prompt, request), { status: 201 });
  },
);
