import type { CookieOptionsWithName } from "@supabase/ssr";

/**
 * Overrides `@supabase/ssr`'s own defaults for the session cookie: `sameSite: "lax"` (kept — this
 * is also what `docs/API.md`'s CSRF section documents), no `secure` at all, and `httpOnly: false`
 * (the library assumes its browser client needs to read the cookie itself via `document.cookie`).
 *
 * `src/lib/supabase/client.ts` (the browser client) is not imported anywhere in this app: every
 * auth flow is a server Route Handler, so nothing needs JavaScript access to this cookie, and
 * `httpOnly` closes off an XSS's easiest path to a live session. `secure` is conditional so
 * `http://localhost` dev (and the local nginx proxy, also plain http) keep working; Vercel and any
 * real deployment are https-only, so production always gets it.
 *
 * Shared by every place that builds a Supabase server client (`server.ts` for Route Handlers and
 * Server Components, `session.ts` for `src/proxy.ts`), so the cookie is never set with one policy
 * and read back expecting another.
 */
export const AUTH_COOKIE_OPTIONS: CookieOptionsWithName = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
};
