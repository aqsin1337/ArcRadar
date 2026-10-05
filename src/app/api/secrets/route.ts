import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { listSecrets } from "@/lib/secrets/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/secrets
 * The settings an administrator can save in the app, with where each one comes from (the app, the
 * server environment, or nowhere). A saved key is never returned, only its last characters.
 */
export const GET = protectedRoute({ permissions: ["integrations:manage"] }, async () =>
  ok(await listSecrets()),
);
