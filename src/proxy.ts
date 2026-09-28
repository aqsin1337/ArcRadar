import { NextResponse, type NextRequest } from "next/server";
import { isPublicPath, loginPathFor } from "@/lib/auth/routes";
import { updateSession } from "@/lib/supabase/session";

/**
 * Refreshes the session cookies and sends visitors with no session to the sign-in page (with the
 * page they wanted in `?next=`). This is only a shortcut: it never redirects signed-in users away
 * from auth pages (a stale-but-valid token could then loop with the layout guard), and it decides
 * nothing when the session state is unknown. Real checks live in the `(app)` layout and API routes.
 */
export async function proxy(request: NextRequest) {
  const { response, signedIn } = await updateSession(request);
  const { pathname, search } = request.nextUrl;

  if (signedIn !== false || isPublicPath(pathname)) return response;

  const redirect = NextResponse.redirect(new URL(loginPathFor(pathname, search), request.url));
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
