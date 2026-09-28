import "server-only";
import { unstable_rethrow } from "next/navigation";
import type { NextRequest } from "next/server";
import type { ApiKeyScope } from "@/lib/api-keys/constants";
import { bearerToken } from "@/lib/api-keys/keys";
import { verifyApiKey } from "@/lib/api-keys/service";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import { finalize, toErrorResponse } from "./handler";

export type IngestRouteContext = {
  request: NextRequest;
  requestId: string;
  /** The API key that made the request, and the account it acts for. */
  principal: ApiKeyPrincipal;
};

/**
 * The third route wrapper, next to `publicRoute` and `protectedRoute`, for machines (a Wazuh
 * Manager, a script): it authenticates an API key instead of a session. The key is read from
 * `Authorization: Bearer <key>`, hashed and looked up; a key that is unknown, revoked, expired,
 * owned by a disabled or demoted account, or missing the scope is refused before the handler runs.
 *
 * There are no cookies here, so there is no same-origin check (that defence is for browsers) and no
 * user-scoped Supabase client: a handler writes through a narrow, service-role-only path such as the
 * `ingest_telemetry()` database function. Errors use the same envelope as every other route.
 */
export function ingestRoute(
  options: { scope: ApiKeyScope },
  handler: (context: IngestRouteContext) => Promise<Response>,
) {
  return async (request: NextRequest): Promise<Response> => {
    const requestId = crypto.randomUUID();
    try {
      const principal = await verifyApiKey(
        bearerToken(request.headers.get("authorization")),
        options.scope,
      );
      const response = await handler({ request, requestId, principal });
      return finalize(response, requestId);
    } catch (error) {
      // Framework control-flow errors must reach Next.js untouched, as in the other wrappers.
      unstable_rethrow(error);
      return finalize(toErrorResponse(error, request, requestId), requestId);
    }
  };
}
