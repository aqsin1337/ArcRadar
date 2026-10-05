import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateDetectionRuleSchema } from "@/lib/detection-rules/schema";
import { deleteDetectionRule, updateDetectionRule } from "@/lib/detection-rules/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** PATCH /api/detection-rules/:id — needs rules:manage. The id itself cannot be changed. */
export const PATCH = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateDetectionRuleSchema);
    return ok(await updateDetectionRule(auth, Number(params.id), input, request));
  },
);

/** DELETE /api/detection-rules/:id — needs rules:manage. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    await deleteDetectionRule(auth, Number(params.id), request);
    return ok({ deleted: true });
  },
);
