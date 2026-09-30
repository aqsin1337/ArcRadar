import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateWazuhRuleSchema } from "@/lib/wazuh-rules/schema";
import { deleteWazuhRule, getWazuhRule, updateWazuhRule } from "@/lib/wazuh-rules/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/wazuh-rules/:id — needs rules:manage. */
export const GET = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ auth, params }) => ok(await getWazuhRule(auth.supabase, Number(params.id))),
);

/** PATCH /api/wazuh-rules/:id — edit the rule's fields. Needs rules:manage. The id cannot change. */
export const PATCH = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateWazuhRuleSchema);
    return ok(await updateWazuhRule(auth, Number(params.id), input, request));
  },
);

/** DELETE /api/wazuh-rules/:id — a draft or rejected rule only (a pushed one is a file on GitHub). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    await deleteWazuhRule(auth, Number(params.id), request);
    return ok({ deleted: true });
  },
);
