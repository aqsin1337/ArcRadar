import { mkdirSync } from "node:fs";
import { expect, test as setup } from "@playwright/test";
import { AUTH_DIR, DEMO_PASSWORD, STORAGE } from "./support";

// Signs in once per role through the API and saves the cookies, so the browser tests start signed in
// without spending a login (Supabase rate-limits sign-ins) on every test.
mkdirSync(AUTH_DIR, { recursive: true });

for (const [role, email] of [
  ["viewer", "viewer@arcradar.test"],
  ["analyst", "analyst@arcradar.test"],
  ["admin", "admin@arcradar.test"],
] as const) {
  setup(`sign in as ${role}`, async ({ request }) => {
    const response = await request.post("/api/auth/login", {
      data: { email, password: DEMO_PASSWORD },
    });
    expect(response.status(), await response.text()).toBe(200);
    await request.storageState({ path: STORAGE[role] });
  });
}
