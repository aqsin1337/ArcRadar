import { readFileSync } from "node:fs";
import { join } from "node:path";

export const DEMO_PASSWORD = "ArcRadar-Demo-1!";
export const AUTH_DIR = join(process.cwd(), "tests", "e2e", ".auth");
export const STORAGE = {
  viewer: join(AUTH_DIR, "viewer.json"),
  analyst: join(AUTH_DIR, "analyst.json"),
  admin: join(AUTH_DIR, "admin.json"),
};

/** Reads local Supabase settings from .env.local (used only for test set-up and clean-up). */
export function localEnv() {
  const env: Record<string, string> = {};
  for (const line of readFileSync(join(process.cwd(), ".env.local"), "utf8").split(/\r?\n/)) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
  }
  return env;
}

/** Service-role REST helper for creating and removing throwaway users. */
export async function adminFetch(path: string, init: RequestInit = {}) {
  const env = localEnv();
  return fetch(`${env.NEXT_PUBLIC_SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "content-type": "application/json",
      ...init.headers,
    },
  });
}
