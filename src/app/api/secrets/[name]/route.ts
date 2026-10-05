import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { listSecrets, removeSecret, saveSecret } from "@/lib/secrets/service";

export const dynamic = "force-dynamic";

type Params = { name: string };

const putSchema = z.strictObject({ value: z.string().max(1000) });

/**
 * PUT /api/secrets/:name  { value }
 * Saves one provider key (encrypted) so ArcRadar uses it instead of a server variable. Needs
 * integrations:manage. The value is validated per setting and never written to the audit trail.
 */
export const PUT = protectedRoute<Params>(
  { permissions: ["integrations:manage"] },
  async ({ request, auth, params }) => {
    const { value } = await parseJsonBody(request, putSchema);
    await saveSecret(auth, params.name, value, request);
    return ok(await listSecrets());
  },
);

/** DELETE /api/secrets/:name: removes the saved key; the server variable (if any) applies again. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["integrations:manage"] },
  async ({ request, auth, params }) => {
    await removeSecret(auth, params.name, request);
    return ok(await listSecrets());
  },
);
