import "server-only";
import { unstable_rethrow } from "next/navigation";
import { cache } from "react";
import { ApiError } from "@/lib/api/errors";
import { EnvError } from "@/lib/env/parse";
import { logError } from "@/lib/log";
import { createClient } from "@/lib/supabase/server";
import { requireAuth, type AuthContext } from "./context";

/** What a page needs to know about the visitor. Pages branch on `status`; nothing throws. */
export type PageAuth =
  | { status: "ok"; auth: AuthContext }
  | { status: "signed_out" }
  | { status: "disabled" }
  | { status: "unavailable" };

/**
 * Server-verified session for Server Components (`getUser()` against the auth server plus the
 * profile through RLS, never just the cookie). Wrapped in React `cache`, so a layout and its page
 * share one lookup per request. Use this, not proxy.ts, as the real page guard: the proxy only does
 * an optimistic redirect.
 */
export const getPageAuth = cache(async (): Promise<PageAuth> => {
  try {
    const supabase = await createClient();
    return { status: "ok", auth: await requireAuth(supabase) };
  } catch (error) {
    // `cookies()` signals "this page is dynamic" by throwing during prerender. Let Next.js see it.
    unstable_rethrow(error);
    if (error instanceof ApiError) {
      if (error.code === "UNAUTHENTICATED") return { status: "signed_out" };
      if (error.code === "ACCOUNT_DISABLED" || error.code === "FORBIDDEN") {
        return { status: "disabled" };
      }
    }
    // Auth backend down, database error, or missing configuration.
    logError("page.auth_unavailable", error, {
      reason: error instanceof EnvError ? "not_configured" : undefined,
    });
    return { status: "unavailable" };
  }
});

/**
 * The caller's context inside a page under the `(app)` layout, or null. The layout already shows the
 * signed-out, disabled and unavailable screens, so a page that gets null should just render nothing
 * (throwing a redirect here would override what the layout chose to show).
 */
export async function getPageAuthContext(): Promise<AuthContext | null> {
  const result = await getPageAuth();
  return result.status === "ok" ? result.auth : null;
}
