import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { revokeApiKey } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

/**
 * DELETE /api/api-keys/:id — revokes a key you can see (your own; an administrator can revoke anyone's).
 * It stops working at once. Revoking a revoked key is harmless (`200` again). Needs api_keys:manage_own.
 */
export const DELETE = protectedRoute<{ id: string }>(
  { permissions: ["api_keys:manage_own"] },
  async ({ request, auth, params }) => ok(await revokeApiKey(auth, params.id, request)),
);
