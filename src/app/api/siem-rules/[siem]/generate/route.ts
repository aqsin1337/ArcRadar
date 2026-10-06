import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { userSubject } from "@/lib/rate-limit/service";
import { requireSiem } from "@/lib/siem-rules/params";
import { generateSiemRuleSchema } from "@/lib/siem-rules/schema";
import { generateSiemRule } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string };

/**
 * POST /api/siem-rules/:siem/generate  { prompt } — the active AI provider drafts a rule from a
 * plain-language description. The draft is validated like a hand-written rule and stored as a
 * draft; nothing is pushed. Needs rules:manage and ai:use. 503 when no provider is ready.
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["rules:manage", "ai:use"],
    rateLimit: { routeClass: "siemRuleGenerateByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) => {
    const siem = requireSiem(params.siem);
    const { prompt } = await parseJsonBody(request, generateSiemRuleSchema);
    return ok(await generateSiemRule(auth, siem, prompt, request), { status: 201 });
  },
);
