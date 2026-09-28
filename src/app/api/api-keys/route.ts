import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { createApiKeySchema } from "@/lib/api-keys/schema";
import { createApiKey, listApiKeys } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/api-keys — your API keys (an administrator sees everyone's): name, prefix, scopes, status
 * (`active`, `expired`, `revoked`), last used, expiry. Never the key or its hash. Needs api_keys:manage_own.
 */
export const GET = protectedRoute({ permissions: ["api_keys:manage_own"] }, async ({ auth }) =>
  ok(await listApiKeys(auth)),
);

/**
 * POST /api/api-keys  { name, scopes: ["ingest:wazuh"], expires_in_days? } — needs api_keys:manage_own,
 * and the caller's role must be allowed the scope (`ingest:wazuh` needs events:write, administrators).
 * `expires_in_days` is 1-365 (default 365); `null` never expires. Answers `201 { key, api_key }`:
 * **`key` is shown once and cannot be read again**, only its SHA-256 hash is stored. At most 10 usable
 * keys per person (`409`).
 */
export const POST = protectedRoute(
  { permissions: ["api_keys:manage_own"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createApiKeySchema);
    return ok(await createApiKey(auth, input, request), { status: 201 });
  },
);
