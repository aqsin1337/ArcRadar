import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { userSubject } from "@/lib/rate-limit/service";
import { pushWazuhRule } from "@/lib/wazuh-rules/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/**
 * POST /api/wazuh-rules/:id/push — commits the rule's generated XML to the rules repository on
 * GitHub. Needs rules:manage. 503 when GitHub is not configured or refuses the token.
 */
export const POST = protectedRoute<Params>(
  {
    permissions: ["rules:manage"],
    rateLimit: { routeClass: "wazuhRulePushByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth, params }) => ok(await pushWazuhRule(auth, Number(params.id), request)),
);
