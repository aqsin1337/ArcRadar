/**
 * Browser-side helper for the ArcRadar JSON API (see docs/API.md). It never throws for HTTP errors or
 * network failures: callers branch on `result.ok` and show `result.message` (already user-friendly).
 */
export type ApiFailure = {
  ok: false;
  status: number;
  code: string;
  message: string;
  /** First validation message per field path, from a 422 response. */
  fieldErrors: Record<string, string>;
  /** The error's `details` as sent by the API (for example `existing_id` on a 409). */
  details?: unknown;
};
export type ApiSuccess<T> = { ok: true; data: T };
export type ApiResult<T> = ApiSuccess<T> | ApiFailure;

const FRIENDLY_MESSAGES: Record<string, string> = {
  NETWORK_ERROR: "Can't reach the server. Check your connection and try again.",
  BAD_RESPONSE: "The server sent an unexpected response. Try again in a moment.",
  RATE_LIMITED: "Too many attempts. Wait a few minutes and try again.",
  DEPENDENCY_UNAVAILABLE: "The service is temporarily unavailable. Try again shortly.",
  INTERNAL_ERROR: "Something went wrong on our side. Try again.",
};

function failure(
  status: number,
  code: string,
  message: string,
  fieldErrors: Record<string, string> = {},
  details?: unknown,
): ApiFailure {
  return {
    ok: false,
    status,
    code,
    message: FRIENDLY_MESSAGES[code] ?? message,
    fieldErrors,
    ...(details === undefined ? {} : { details }),
  };
}

function issuesToFieldErrors(details: unknown): Record<string, string> {
  const issues = (details as { issues?: unknown } | null | undefined)?.issues;
  if (!Array.isArray(issues)) return {};
  const fieldErrors: Record<string, string> = {};
  for (const issue of issues) {
    const path = typeof issue?.path === "string" ? issue.path : "";
    if (typeof issue?.message === "string" && !(path in fieldErrors)) {
      fieldErrors[path] = issue.message;
    }
  }
  return fieldErrors;
}

/** Turns an HTTP status plus parsed body into an ApiResult. Exported for unit tests. */
export function parseEnvelope<T>(status: number, json: unknown): ApiResult<T> {
  const body = json as {
    success?: unknown;
    data?: T;
    error?: { code?: unknown; message?: unknown; details?: unknown } | null;
  } | null;

  if (body && typeof body === "object" && body.success === true) {
    return { ok: true, data: body.data as T };
  }
  if (body && typeof body === "object" && body.success === false && body.error) {
    const { code, message, details } = body.error;
    return failure(
      status,
      typeof code === "string" ? code : "UNKNOWN_ERROR",
      typeof message === "string" ? message : "The request failed.",
      issuesToFieldErrors(details),
      details,
    );
  }
  // A proxy error page (for example nginx 502) or an empty body.
  return failure(status, status >= 500 ? "DEPENDENCY_UNAVAILABLE" : "BAD_RESPONSE", "");
}

export async function apiFetch<T>(
  path: string,
  init: {
    method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
    body?: unknown;
    /** Lets the caller cancel a request that is no longer needed (for example a stale search). */
    signal?: AbortSignal;
  } = {},
): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      headers: init.body === undefined ? undefined : { "content-type": "application/json" },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      credentials: "same-origin",
      cache: "no-store",
      signal: init.signal
        ? AbortSignal.any([init.signal, AbortSignal.timeout(20_000)])
        : AbortSignal.timeout(20_000),
    });
  } catch (error) {
    // A request the caller cancelled is not an error worth showing.
    if (init.signal?.aborted) return failure(0, "ABORTED", "");
    void error;
    return failure(0, "NETWORK_ERROR", "");
  }

  let json: unknown = null;
  try {
    json = await response.json();
  } catch {
    // Not JSON: handled by parseEnvelope.
  }
  return parseEnvelope<T>(response.status, json);
}
