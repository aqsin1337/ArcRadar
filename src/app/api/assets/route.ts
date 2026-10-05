import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { assetListQuerySchema } from "@/lib/telemetry/schema";
import { listAssets } from "@/lib/telemetry/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/assets?source&origin&sort&order&page&page_size — the machines telemetry comes from (created
 * by ingestion; `origin` says whether they are live or demo). `sort`: `last_seen` (default), `first_seen`,
 * `name`. Read-only: assets are never written through the API. Needs events:read.
 */
export const GET = protectedRoute({ permissions: ["events:read"] }, async ({ request, auth }) => {
  const query = parseQuery(request, assetListQuerySchema);
  return ok(await listAssets(auth.supabase, query));
});
