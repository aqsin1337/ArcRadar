/** Pages a signed-out visitor may open. Everything else is deny-by-default. */
const PUBLIC_PAGES = new Set(["/", "/login", "/signup", "/forgot-password", "/design"]);

/**
 * Whether `pathname` can be opened without a session. API routes answer 401 JSON themselves,
 * `/auth/*` is the email-link callback, and the listed pages are the auth pages. Unknown paths are
 * treated as protected, so a typo sends a signed-out visitor to sign in rather than to a 404 that
 * reveals which paths exist.
 */
export function isPublicPath(pathname: string): boolean {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return (
    path === "/api" ||
    path.startsWith("/api/") ||
    path.startsWith("/auth/") ||
    PUBLIC_PAGES.has(path)
  );
}

/** `/login?next=<original path>`; the sign-in page validates `next` again before using it. */
export function loginPathFor(pathname: string, search = ""): string {
  return `/login?next=${encodeURIComponent(pathname + search)}`;
}
