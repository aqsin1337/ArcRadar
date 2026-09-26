import { z } from "zod";
import { parseEnv } from "./parse";

// Client-safe variables (NEXT_PUBLIC_ prefix). These end up in the browser bundle, so they must
// never hold secrets. The anon/publishable key is designed to be public; access is enforced by RLS.
const supabaseSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
});

const publicEnvSchema = supabaseSchema.extend({
  NEXT_PUBLIC_APP_URL: z.url().default("http://localhost:3000"),
});

export type PublicEnv = z.output<typeof publicEnvSchema>;

// Next.js inlines NEXT_PUBLIC_* values at build time, which only works for literal
// `process.env.NEXT_PUBLIC_X` references. Do not build these names dynamically.
function readPublicEnv() {
  return {
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL || undefined,
  };
}

export function parsePublicEnv(source: unknown): PublicEnv {
  return parseEnv(publicEnvSchema, source, "public");
}

export function getPublicEnv(): PublicEnv {
  return parsePublicEnv(readPublicEnv());
}

export function isSupabaseConfigured(): boolean {
  return supabaseSchema.safeParse(readPublicEnv()).success;
}

/**
 * Shows the "fill in a demo account" buttons on the sign-in page. `npm run db:env` turns it on for
 * the local stack, whose seed creates the demo users; leave it unset on any hosted deployment.
 */
export function isDemoLoginsEnabled(): boolean {
  return process.env.NEXT_PUBLIC_DEMO_LOGINS === "true";
}
