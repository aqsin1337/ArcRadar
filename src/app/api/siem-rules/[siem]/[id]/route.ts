import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { getDialect } from "@/lib/siem-rules/dialects";
import { requireSiem } from "@/lib/siem-rules/params";
import { updateSiemRuleSchema } from "@/lib/siem-rules/schema";
import { deleteSiemRule, getSiemRule, updateSiemRule } from "@/lib/siem-rules/service";

export const dynamic = "force-dynamic";

type Params = { siem: string; id: string };

/** GET /api/siem-rules/:siem/:id — needs rules:manage. */
export const GET = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ auth, params }) =>
    ok(await getSiemRule(auth.supabase, requireSiem(params.siem), params.id)),
);

/** PATCH /api/siem-rules/:siem/:id — edit the rule's fields. Needs rules:manage. The key cannot change. */
export const PATCH = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const siem = requireSiem(params.siem);
    const input = await parseJsonBody(request, updateSiemRuleSchema(getDialect(siem)));
    return ok(await updateSiemRule(auth, siem, params.id, input, request));
  },
);

/** DELETE /api/siem-rules/:siem/:id — a draft or rejected rule only (a pushed one is a file on GitHub). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    await deleteSiemRule(auth, requireSiem(params.siem), params.id, request);
    return ok({ deleted: true });
  },
);
