import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { getPublicEnv, isSupabaseConfigured } from "@/lib/env/public";
import type { Database } from "@/types/database";

export type SessionUpdate = {
  response: NextResponse;
  /**
   * Whether the request carries a usable session token: true/false, or null when that could not be
   * determined (Supabase not configured or unreachable). Optimistic only: pages and API routes
   * re-verify with `getUser()` before trusting it.
   */
  signedIn: boolean | null;
};

/**
 * Keeps the Supabase auth cookies fresh on every matched request (used by src/proxy.ts) and reports
 * whether a session is present. It does not protect routes by itself: API handlers guard themselves
 * (see `protectedRoute` in lib/api/handler.ts) and the `(app)` layout verifies the session.
 */
export async function updateSession(request: NextRequest): Promise<SessionUpdate> {
  let response = NextResponse.next({ request });
  if (!isSupabaseConfigured()) return { response, signedIn: null };

  const env = getPublicEnv();
  const supabase = createServerClient<Database>(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet, headers) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options),
          );
          // Stops CDNs from caching a response that carries Set-Cookie.
          Object.entries(headers).forEach(([key, value]) => response.headers.set(key, value));
        },
      },
    },
  );

  let signedIn: boolean | null = null;
  try {
    const { data } = await supabase.auth.getClaims();
    signedIn = Boolean(data?.claims);
  } catch {
    // Auth backend unreachable: leave it undecided. Server code that needs a user checks again.
  }

  return { response, signedIn };
}
