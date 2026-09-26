/**
 * Returns `next` only when it is a same-site absolute path such as `/dashboard?tab=1`. Anything
 * that could leave the site (`//evil.com`, `/\evil.com`, `https://...`, `javascript:`) or contains
 * control characters falls back to `fallback`, which prevents open redirects after login.
 */
export function safeRedirectPath(next: string | null | undefined, fallback = "/"): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) {
    return fallback;
  }
  if (/[\u0000-\u001f\u007f]/.test(next)) return fallback;
  return next;
}
