import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { userSubject } from "@/lib/rate-limit/service";
import { requireSiem } from "@/lib/siem-rules/params";
import { pushSiemRule } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string; id: string };

/**
 * POST /api/siem-rules/:siem/:id/push — commits the rule's generated file to the rules repository
 * on GitHub. Needs rules:manage. 503 when GitHub is not configured or refuses the token.
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["rules:manage"],
    rateLimit: { routeClass: "siemRulePushByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) =>
    ok(await pushSiemRule(auth, requireSiem(params.siem), params.id, request)),
);
