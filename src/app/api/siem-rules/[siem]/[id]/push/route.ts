import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { userSubject } from "@/lib/rate-limit/service";
import { requireSiem } from "@/lib/siem-rules/params";
import { pushSiemRuleQuerySchema } from "@/lib/siem-rules/schema";
import { pushSiemRule } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string; id: string };

/**
 * POST /api/siem-rules/:siem/:id/push[?mode=test|live] — commits the rule's generated file to the rules
 * repository on GitHub. Needs rules:manage. `mode=test` pushes it in test mode: the SIEM loads it but it never
 * runs on a schedule and has no action, so it can be backtested without alerting; without a mode it is live.
 * 503 when GitHub is not configured or refuses the token.
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["rules:manage"],
    rateLimit: { routeClass: "siemRulePushByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) => {
    const { mode } = parseQuery(request, pushSiemRuleQuerySchema);
    return ok(await pushSiemRule(auth, requireSiem(params.siem), params.id, mode, request));
  },
);
