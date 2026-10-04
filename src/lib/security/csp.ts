/**
 * This app's Content-Security-Policy, nonce-based per
 * `node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md` ("Nonces"): every page
 * is already dynamically rendered (session-gated), so there is no static-generation conflict, and
 * the app writes no inline `<script>`/`<style>` and no `dangerouslySetInnerHTML` of its own — only
 * Next's own framework scripts and `next/font`'s injected `@font-face` rule need the nonce, which
 * Next attaches to those automatically once it sees this header on the request.
 *
 * `'strict-dynamic'` makes browsers that support it ignore `'self'`/the nonce allowlist for
 * scripts loaded *by* a nonce'd script (Next's own bundle splitting) and trust only the chain of
 * trust from the nonce; `'self'` and the nonce remain as the fallback for browsers that do not.
 * `'unsafe-eval'` is dev-only (React's own debug-mode eval for reconstructed stack traces; neither
 * React nor Next use `eval` in a production build). `connect-src 'self'` is enough because the
 * browser never talks to Supabase directly (`src/lib/supabase/client.ts` is not imported anywhere:
 * every auth and data flow is a same-origin call to `/api/*`, `apiFetch`'s only mode).
 */
export function buildCsp(nonce: string, isProduction: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isProduction ? "" : " 'unsafe-eval'"}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    // Plain http dev (including the local nginx proxy) must not be told to upgrade: there is no
    // https to upgrade to there.
    ...(isProduction ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
}
