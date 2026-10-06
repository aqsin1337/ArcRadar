import "server-only";
import { isDemoLoginsEnabled } from "@/lib/env/public";

// Public credentials of the users created by supabase/seed.sql (see docs/LOCAL_DEVELOPMENT.md). They
// exist only in a local database. This module is server-only on purpose: the values reach the browser
// only when NEXT_PUBLIC_DEMO_LOGINS is set, never as part of the shipped JavaScript bundle.
const DEMO_PASSWORD = "ArcRadar-Demo-1!";
const DEMO_ACCOUNTS = [
  { label: "Admin", email: "admin@arcradar.test" },
  { label: "SOC L2", email: "analyst@arcradar.test" },
  { label: "SOC L1", email: "l1@arcradar.test" },
  { label: "Viewer", email: "viewer@arcradar.test" },
] as const;

export type DemoLogins = {
  password: string;
  accounts: readonly { label: string; email: string }[];
};

/** The demo accounts for the sign-in page, or null when demo logins are switched off (the default). */
export function getDemoLogins(): DemoLogins | null {
  return isDemoLoginsEnabled() ? { password: DEMO_PASSWORD, accounts: DEMO_ACCOUNTS } : null;
}
