import "server-only";
import { unstable_rethrow } from "next/navigation";
import type { NextRequest } from "next/server";
import { ZodError } from "zod";
import { writeAuditLog } from "@/lib/audit/write";
import {
  assertPermissions,
  requireAuth,
  type AuthClient,
  type AuthContext,
} from "@/lib/auth/context";
import { EnvError } from "@/lib/env/parse";
import { logError } from "@/lib/log";
import type { Permission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import { ApiError, apiErrors } from "./errors";
import { assertSameOrigin } from "./origin";
import { fail } from "./response";
import { formatIssues } from "./validate";

type RouteParams = Record<string, string | string[] | undefined>;

type BaseContext<P> = {
  request: NextRequest;
  params: P;
  requestId: string;
  /** Acts as the signed-in user (cookies), so RLS applies. */
  supabase: AuthClient;
};

export type PublicRouteContext<P = RouteParams> = BaseContext<P>;
export type ProtectedRouteContext<P = RouteParams> = BaseContext<P> & { auth: AuthContext };

type NextRouteContext<P> = { params: Promise<P> };

type RouteOptions = { protected: boolean; permissions: readonly Permission[] };

function toErrorResponse(error: unknown, request: Request, requestId: string) {
  if (error instanceof ApiError) {
    return fail(error.status, error.code, error.message, error.details, error.headers);
  }
  if (error instanceof ZodError) {
    const validation = apiErrors.validation(formatIssues(error));
    return fail(validation.status, validation.code, validation.message, validation.details);
  }

  const path = new URL(request.url).pathname;
  if (error instanceof EnvError) {
    logError("api.not_configured", error, { request_id: requestId, path });
    const unavailable = apiErrors.unavailable("The service is not configured.");
    return fail(unavailable.status, unavailable.code, unavailable.message);
  }

  logError("api.unhandled_error", error, { request_id: requestId, method: request.method, path });
  const internal = apiErrors.internal();
  return fail(internal.status, internal.code, internal.message);
}

function finalize(response: Response, requestId: string) {
  // Responses depend on the session cookie and must never be cached by a CDN or the browser.
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("x-request-id", requestId);
  return response;
}

async function execute<P>(
  request: NextRequest,
  routeContext: NextRouteContext<P> | undefined,
  options: RouteOptions,
  handler: (context: BaseContext<P> & { auth: AuthContext | undefined }) => Promise<Response>,
): Promise<Response> {
  const requestId = crypto.randomUUID();
  try {
    assertSameOrigin(request);

    const supabase = await createClient();
    const params = routeContext ? await routeContext.params : ({} as P);

    let auth: AuthContext | undefined;
    if (options.protected) {
      auth = await requireAuth(supabase);
      try {
        assertPermissions(auth, options.permissions);
      } catch (error) {
        await writeAuditLog(
          {
            action: "authz.denied",
            userId: auth.user.id,
            entityType: "route",
            entityId: new URL(request.url).pathname,
            metadata: {
              method: request.method,
              required_permissions: options.permissions,
              role: auth.profile.role,
            },
          },
          request,
        );
        throw error;
      }
    }

    const response = await handler({ request, params, requestId, supabase, auth });
    return finalize(response, requestId);
  } catch (error) {
    // Framework control-flow errors (for example the dynamic-rendering signal from `cookies()`) must
    // reach Next.js untouched; everything else becomes an envelope response.
    unstable_rethrow(error);
    return finalize(toErrorResponse(error, request, requestId), requestId);
  }
}

/**
 * Wraps a Route Handler that does not need a signed-in user (login, signup, ...). Provides the
 * same-origin check, `no-store` caching, a request id, and mapping of every thrown error to the
 * `{ success, data, error }` envelope. Handlers return `ok(...)` and throw `apiErrors.*`.
 */
export function publicRoute<P = RouteParams>(
  handler: (context: PublicRouteContext<P>) => Promise<Response>,
) {
  return (request: NextRequest, routeContext?: NextRouteContext<P>) =>
    execute(request, routeContext, { protected: false, permissions: [] }, handler);
}

/**
 * Like `publicRoute`, but requires a valid session for an active account and, when `permissions` is
 * given, every listed permission (denials are audited). This is a fast application-side check; RLS
 * in the database still decides what the queries can read and write.
 */
export function protectedRoute<P = RouteParams>(
  options: { permissions?: readonly Permission[] },
  handler: (context: ProtectedRouteContext<P>) => Promise<Response>,
) {
  return (request: NextRequest, routeContext?: NextRouteContext<P>) =>
    execute(
      request,
      routeContext,
      { protected: true, permissions: options.permissions ?? [] },
      (context) => handler({ ...context, auth: context.auth as AuthContext }),
    );
}
