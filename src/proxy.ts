import { NextResponse, type NextRequest } from "next/server";
import { isPublicPath, loginPathFor } from "@/lib/auth/routes";
import { buildCsp } from "@/lib/security/csp";
import { updateSession } from "@/lib/supabase/session";

/**
 * Refreshes the session cookies and sends visitors with no session to the sign-in page (with the
 * page they wanted in `?next=`). This is only a shortcut: it never redirects signed-in users away
 * from auth pages (a stale-but-valid token could then loop with the layout guard), and it decides
 * nothing when the session state is unknown. Real checks live in the `(app)` layout and API routes.
 *
 * Also carries this request's Content-Security-Policy (`src/lib/security/csp.ts`): set on the
 * mutated request (so Server Components rendered for it apply the nonce to Next's own scripts and
 * styles) and again on every response this function can return, since `NextResponse.next({
 * request })` only forwards the request-side header to the render pipeline, never to the browser.
 */
export async function proxy(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const csp = buildCsp(nonce, process.env.NODE_ENV === "production");
  request.headers.set("x-nonce", nonce);
  request.headers.set("Content-Security-Policy", csp);

  const { response, signedIn } = await updateSession(request);
  response.headers.set("Content-Security-Policy", csp);
  const { pathname, search } = request.nextUrl;

  if (signedIn !== false || isPublicPath(pathname)) return response;

  const redirect = NextResponse.redirect(new URL(loginPathFor(pathname, search), request.url));
  redirect.headers.set("Content-Security-Policy", csp);
  // Keep any cookie changes the session refresh just made (for example clearing an expired token).
  response.cookies.getAll().forEach((cookie) => redirect.cookies.set(cookie));
  const cacheControl = response.headers.get("cache-control");
  if (cacheControl) redirect.headers.set("cache-control", cacheControl);
  return redirect;
}

export const config = {
  // Everything except static assets, the health check and the machine-facing ingest endpoints (an
  // API key, not a session cookie, authenticates those, so there is nothing to refresh or redirect).
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|icon.svg|api/health|api/ingest/|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
