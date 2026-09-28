import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { setIntegrationEnabled } from "@/lib/integrations/service";

export const dynamic = "force-dynamic";

type Params = { provider: string };

const patchSchema = z.strictObject({ enabled: z.boolean() });

/**
 * PATCH /api/integrations/:provider  { enabled }
 * Needs integrations:manage (administrators). The demo provider cannot be turned off. Disabling a
 * live provider stops it being asked even while its server-side key is set.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["integrations:manage"] },
  async ({ request, auth, params }) => {
    const { enabled } = await parseJsonBody(request, patchSchema);
    return ok(await setIntegrationEnabled(auth, params.provider, enabled, request));
  },
);
