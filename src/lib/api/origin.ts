import { apiErrors } from "./errors";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * CSRF defense in depth for cookie-authenticated endpoints (the auth cookies are also SameSite=Lax
 * and bodies must be application/json). Browsers always send `Origin` on cross-site unsafe
 * requests and scripts cannot forge it, so a mismatch with the request host is rejected. Requests
 * without `Origin` (curl, server-to-server, API keys) are not browser-driven and pass through.
 */
export function assertSameOrigin(request: Request) {
  if (SAFE_METHODS.has(request.method.toUpperCase())) return;

  const origin = request.headers.get("origin");
  if (origin === null) return;

  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  let originHost: string | null = null;
  try {
    originHost = new URL(origin).host;
  } catch {
    // "null" and other opaque origins fall through to the rejection below.
  }

  if (!host || originHost !== host) {
    throw apiErrors.forbidden("Cross-origin requests are not allowed.");
  }
}
