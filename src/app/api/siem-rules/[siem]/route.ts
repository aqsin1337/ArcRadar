import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { getDialect } from "@/lib/siem-rules/dialects";
import { requireSiem } from "@/lib/siem-rules/params";
import { createSiemRuleSchema } from "@/lib/siem-rules/schema";
import { createSiemRule, listSiemRules } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string };

/** GET /api/siem-rules/:siem — every rule with its generated file. Needs rules:manage. */
export const GET = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ auth, params }) => ok(await listSiemRules(auth.supabase, requireSiem(params.siem))),
);

/**
 * POST /api/siem-rules/:siem  { rule_key?, name, description?, severity, mitre_ids?, spec } — a
 * hand-written rule, always a draft. `spec` is that SIEM's structured fields. Needs rules:manage.
 */
export const POST = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const siem = requireSiem(params.siem);
    const input = await parseJsonBody(request, createSiemRuleSchema(getDialect(siem)));
    return ok(await createSiemRule(auth, siem, input, request), { status: 201 });
  },
);
