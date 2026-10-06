import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { requireSiem } from "@/lib/siem-rules/params";
import { rejectSiemRuleSchema } from "@/lib/siem-rules/schema";
import { rejectSiemRule } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string; id: string };

/** POST /api/siem-rules/:siem/:id/reject  { reason? } — a draft becomes rejected and never goes to GitHub. */
export const POST = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const siem = requireSiem(params.siem);
    const { reason } = await parseJsonBody(request, rejectSiemRuleSchema);
    return ok(await rejectSiemRule(auth, siem, params.id, reason ?? null, request));
  },
);
