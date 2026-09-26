import "server-only";
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { getPublicEnv } from "@/lib/env/public";
import type { Database } from "@/types/database";

/**
 * Supabase client for Server Components, Route Handlers and Server Actions. It acts as the signed-in
 * user (from the session cookies), so RLS applies. Call `supabase.auth.getUser()` to validate the
 * session before trusting it for anything sensitive.
 */
export async function createClient() {
  const cookieStore = await cookies();
  const env = getPublicEnv();

  return createServerClient<Database>(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options),
            );
          } catch {
            // Called from a Server Component, where cookies are read-only. Safe to ignore:
            // proxy.ts refreshes the session and writes the cookies on the next request.
          }
        },
      },
    },
  );
}
