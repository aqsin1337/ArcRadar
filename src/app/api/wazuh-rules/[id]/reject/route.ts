import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { rejectWazuhRuleSchema } from "@/lib/wazuh-rules/schema";
import { rejectWazuhRule } from "@/lib/wazuh-rules/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** POST /api/wazuh-rules/:id/reject  { reason? } — a draft becomes rejected and never goes to GitHub. */
export const POST = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const { reason } = await parseJsonBody(request, rejectWazuhRuleSchema);
    return ok(await rejectWazuhRule(auth, Number(params.id), reason ?? null, request));
  },
);
