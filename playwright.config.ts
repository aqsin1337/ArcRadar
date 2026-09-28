import { defineConfig, devices } from "@playwright/test";

// End-to-end tests drive a real browser against a RUNNING app and the local Supabase stack:
//   npm run db:start && npm run build && npm run e2e
// They use the Chrome installed on this machine (no browser download); set E2E_CHANNEL=msedge to use Edge.
const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:3000";
const channel = process.env.E2E_CHANNEL ?? "chrome";

export default defineConfig({
  testDir: "tests/e2e",
  outputDir: "test-results",
  // Logins are rate limited by Supabase Auth (30 per 5 minutes per IP), so keep the run sequential.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 7_000 },
  reporter: [["list"]],
  use: {
    baseURL,
    channel,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], channel },
      dependencies: ["setup"],
      testMatch:
        /(auth|app|indicators|intelligence|operations|threat-intel|telemetry|admin|accessibility)\.spec\.ts/,
    },
    {
      name: "mobile",
      use: { ...devices["Pixel 5"], channel },
      dependencies: ["setup"],
      testMatch: /responsive\.spec\.ts/,
    },
    {
      // Manual: SCREENSHOTS=1 npx playwright test --project=screenshots (writes test-results/screens/).
      name: "screenshots",
      use: { ...devices["Desktop Chrome"], channel },
      dependencies: ["setup"],
      testMatch: /screenshots\.spec\.ts/,
    },
  ],
  webServer: {
    command: "npm run start",
    url: `${baseURL}/api/health`,
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
