import { test, type Browser } from "@playwright/test";
import { createHash } from "node:crypto";
import { adminFetch, cleanTelemetry, ingest, STORAGE, wazuhAlerts } from "./support";

// Manual visual review, not part of `npm run e2e`:
//   SCREENSHOTS=1 npx playwright test --project=screenshots
// Writes PNGs to test-results/screens/. `/design` only exists in `next dev` (404 in production builds),
// so point E2E_BASE_URL at a dev server to include it.
test.skip(!process.env.SCREENSHOTS, "manual: set SCREENSHOTS=1");

const DIR = "test-results/screens";
const SIZES = {
  desktop: { width: 1280, height: 800 },
  mobile: { width: 393, height: 852 },
} as const;

async function open(
  browser: Browser,
  baseURL: string,
  size: keyof typeof SIZES,
  theme: string,
  storageState?: string,
) {
  const context = await browser.newContext({
    baseURL,
    viewport: SIZES[size],
    isMobile: size === "mobile",
    hasTouch: size === "mobile",
    storageState,
  });
  await context.addCookies([{ name: "arcradar-theme", value: theme, url: baseURL }]);
  return { context, page: await context.newPage() };
}

for (const theme of ["dark", "light"]) {
  for (const size of ["desktop", "mobile"] as const) {
    test(`signed-out pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme);
      for (const path of ["/login", "/signup", "/forgot-password"]) {
        await page.goto(path);
        await page.waitForLoadState("networkidle");
        await page.screenshot({
          path: `${DIR}/${path.slice(1)}-${theme}-${size}.png`,
          fullPage: true,
        });
      }
      await context.close();
    });

    test(`signed-in pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      await page.goto("/dashboard");
      await page.waitForLoadState("networkidle");
      await page.screenshot({ path: `${DIR}/dashboard-${theme}-${size}.png`, fullPage: true });

      if (size === "mobile") {
        await page.getByRole("button", { name: "Open navigation" }).click();
        await page.waitForTimeout(200);
        await page.screenshot({ path: `${DIR}/drawer-${theme}-${size}.png` });
      }

      await page.goto("/definitely-not-a-page");
      await page.screenshot({ path: `${DIR}/not-found-${theme}-${size}.png` });

      const design = await page.goto("/design");
      if (design?.ok()) {
        await page.waitForLoadState("networkidle");
        await page.screenshot({ path: `${DIR}/design-${theme}-${size}.png`, fullPage: true });
      }
      await context.close();
    });

    test(`indicator pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      // Let hydration finish first: Playwright hides the caret by editing inputs, which React reports
      // as a hydration mismatch when the screenshot lands mid-hydration.
      const shot = async (name: string, fullPage = true) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage });
      };

      await page.goto("/indicators");
      await page.getByRole("table").waitFor();
      await shot("indicators");

      await page.goto("/indicators?q=phishing&verdict=malicious&sort=confidence&order=desc");
      await page.getByRole("table").waitFor();
      await shot("indicators-filtered");

      await page.goto("/indicators?q=zzz-nothing-matches");
      await page.getByText("No indicators match").waitFor();
      await shot("indicators-empty");

      await page.goto("/indicators?q=198.51.100.23");
      await page.getByRole("link", { name: "198.51.100.23", exact: true }).first().click();
      await page.getByTestId("indicator-value").waitFor();
      await shot("indicator-detail");

      await page.goto("/indicators/new");
      await page.getByRole("form", { name: "New indicator" }).waitFor();
      await shot("indicator-new");

      await page.getByLabel("Value").fill("999.1.1.1");
      await page.getByLabel("Value").blur();
      await page.getByRole("button", { name: "Create indicator" }).click();
      await shot("indicator-new-errors");

      await page.goto("/indicators?q=harbor");
      await page.getByRole("table").waitFor();
      await page
        .getByRole("link", { name: "harbor-lights-c2.example", exact: true })
        .first()
        .click();
      await page.getByTestId("indicator-value").waitFor();
      await page.getByRole("link", { name: "Edit" }).click();
      await page.getByRole("form", { name: "Edit indicator" }).waitFor();
      await shot("indicator-edit");

      await page.goBack();
      await page.getByRole("button", { name: "Delete" }).click();
      await page.getByRole("dialog").waitFor();
      await shot("indicator-delete-dialog", false);
      await page.keyboard.press("Escape");

      await page.goto("/dashboard");
      const search = page.getByRole("combobox", { name: "Search ArcRadar" });
      await search.fill("harbor");
      await page.getByRole("listbox").waitFor();
      await page
        .getByRole("option", { name: /harbor-lights-c2/ })
        .first()
        .waitFor();
      await shot("global-search", false);
      await context.close();
    });

    test(`intelligence pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.analyst);
      const shot = async (name: string) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage: true });
      };
      const sample1 = createHash("sha256").update("arcradar-demo-sample-1").digest("hex");
      const lookups: [string, string][] = [
        ["intel-ip-start", "/intelligence/ip"],
        ["intel-ip", "/intelligence/ip?q=198.51.100.23"],
        ["intel-ip-benign", "/intelligence/ip?q=8.8.8.8"],
        ["intel-ip-no-record", "/intelligence/ip?q=203.0.113.190"],
        ["intel-ip-invalid", "/intelligence/ip?q=login.example"],
        ["intel-domain", "/intelligence/domain?q=harbor-lights-c2.example"],
        [
          "intel-url",
          `/intelligence/url?q=${encodeURIComponent("http://invoice-download.example/files/invoice_2026.zip")}`,
        ],
        ["intel-hash", `/intelligence/hash?q=${sample1}`],
      ];
      for (const [name, path] of lookups) {
        await page.goto(path);
        await page.getByRole("heading", { level: 1 }).waitFor();
        await shot(name);
      }
      await context.close();
    });

    // Needs a server started with provider keys (fake ones are fine: the providers answer 401 and the
    // page falls back to demo data): SCREENSHOTS=1 SCREENSHOT_FALLBACK=1 with VIRUSTOTAL_API_KEY set.
    test(`live provider fallback, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      test.skip(!process.env.SCREENSHOT_FALLBACK, "manual: needs a server with provider keys");
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.analyst);
      await page.goto("/intelligence/ip?q=8.8.8.8");
      await page.getByTestId("intel-result").waitFor();
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500);
      await page.screenshot({
        path: `${DIR}/intel-ip-fallback-${theme}-${size}.png`,
        fullPage: true,
      });
      await context.close();
    });

    test(`vulnerability pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      const shot = async (name: string) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage: true });
      };

      await page.goto("/vulnerabilities");
      await page.getByRole("table", { name: "Vulnerabilities" }).waitFor();
      await shot("vulnerabilities");

      await page.goto("/vulnerabilities?severity=critical&sort=cvss_score&order=desc");
      await page.getByRole("table", { name: "Vulnerabilities" }).waitFor();
      await shot("vulnerabilities-filtered");

      await page.goto("/vulnerabilities?q=CVE-2099-0001");
      await page.getByText("No vulnerabilities match").waitFor();
      await shot("vulnerabilities-empty");

      await page.goto("/vulnerabilities/CVE-2021-44228");
      await page.getByTestId("vulnerability-id").waitFor();
      await shot("vulnerability-detail");
      await context.close();
    });

    test(`alert and investigation pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      const shot = async (name: string, fullPage = true) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage });
      };

      await page.goto("/alerts");
      await page.getByRole("table", { name: "Alerts" }).waitFor();
      await shot("alerts");

      await page.goto("/alerts?status=new&sort=severity&order=desc");
      await page.getByRole("table", { name: "Alerts" }).waitFor();
      await shot("alerts-filtered");

      await page.goto("/alerts?q=zzz-nothing-matches");
      await page.getByText("No alerts match").waitFor();
      await shot("alerts-empty");

      await page.goto("/alerts?q=beacon");
      await page.locator("tbody tr").first().getByRole("link").first().click();
      await page.getByTestId("alert-title").waitFor();
      await shot("alert-detail");

      await page.goto("/alerts/new");
      await page.getByRole("form", { name: "New alert" }).waitFor();
      await page.getByRole("button", { name: "Create alert" }).click();
      await shot("alert-new-errors");

      await page.goto("/investigations");
      await page.getByRole("table", { name: "Investigations" }).waitFor();
      await shot("investigations");

      await page.goto("/investigations?status=investigating&sort=priority&order=desc");
      await page.getByRole("table", { name: "Investigations" }).waitFor();
      await shot("investigations-filtered");

      await page.goto("/investigations?q=Harbor%20Lights%20C2");
      await page.locator("tbody tr").first().getByRole("link").first().click();
      await page.getByTestId("investigation-title").waitFor();
      await shot("investigation-detail");

      await page.getByRole("button", { name: "Delete", exact: true }).click();
      await page.getByRole("dialog").waitFor();
      await shot("investigation-delete-dialog", false);
      await page.keyboard.press("Escape");

      await page.goto("/investigations/new");
      await page.getByRole("form", { name: "New investigation" }).waitFor();
      await shot("investigation-new");
      await context.close();
    });

    test(`telemetry pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      const shot = async (name: string, fullPage = true) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage });
      };
      const marker = `SHOT-TEL-${theme}-${size}`;
      try {
        // Before anything arrives from a sensor, then after a batch from a Wazuh Manager.
        await page.goto("/telemetry");
        await page.getByRole("heading", { level: 1, name: "Telemetry" }).waitFor();
        await shot("telemetry-before");

        const created = await page.request.post("/api/api-keys", {
          data: { name: `${marker} key`, scopes: ["ingest:wazuh"], expires_in_days: 1 },
        });
        const { key } = (await created.json()).data as { key: string };
        await ingest(key, wazuhAlerts(marker));

        await page.goto("/telemetry");
        await page.getByRole("heading", { level: 1, name: "Telemetry" }).waitFor();
        await shot("telemetry");

        await page.goto("/telemetry?source=wazuh&severity=high");
        await page.getByRole("region", { name: "Events", exact: true }).waitFor();
        await shot("telemetry-filtered");

        // The sample batch holds levels 3, 10 and 12 (info, high, high): nothing here is critical.
        await page.goto("/telemetry?source=wazuh&severity=critical");
        await page.getByText("No events match").waitFor();
        await shot("telemetry-empty");

        await page.goto(`/alerts?q=${encodeURIComponent(`${marker} multiple`)}`);
        await page.locator("tbody tr").first().getByRole("link").first().click();
        await page.getByTestId("alert-title").waitFor();
        await page.getByText("Raw event data").click();
        await shot("alert-from-sensor");
      } finally {
        await cleanTelemetry(marker);
        await context.close();
      }
    });

    test(`threat intelligence pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      const shot = async (name: string, fullPage = true) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage });
      };
      const open1 = async (list: string, name: string) => {
        await page.goto(list);
        await page.getByRole("table").waitFor();
        await page.getByRole("link", { name, exact: true }).first().click();
        await page.getByTestId("record-title").waitFor();
      };

      await page.goto("/threat-actors");
      await page.getByRole("table", { name: "Threat actors" }).waitFor();
      await shot("threat-actors");
      await page.goto("/threat-actors?q=zzz-nothing-matches");
      await page.getByText("No threat actors match").waitFor();
      await shot("threat-actors-empty");
      await open1("/threat-actors", "Crimson Harbor");
      await shot("threat-actor-detail");
      await page.getByRole("button", { name: "Delete" }).click();
      await page.getByRole("dialog").waitFor();
      await shot("threat-actor-delete-dialog", false);
      await page.keyboard.press("Escape");
      await page.getByRole("link", { name: "Edit" }).click();
      await page.getByRole("form", { name: "Edit threat actor" }).waitFor();
      await shot("threat-actor-edit");

      await page.goto("/threat-actors/new");
      await page.getByRole("form", { name: "New threat actor" }).waitFor();
      await page.getByRole("button", { name: "Create threat actor" }).click();
      await shot("threat-actor-new-errors");

      await page.goto("/campaigns");
      await page.getByRole("table", { name: "Campaigns" }).waitFor();
      await shot("campaigns");
      await open1("/campaigns", "Harbor Lights");
      await shot("campaign-detail");

      await page.goto("/malware");
      await page.getByRole("table", { name: "Malware families" }).waitFor();
      await shot("malware");
      await open1("/malware", "NightLoader");
      await shot("malware-detail");

      await page.goto("/mitre");
      await page.getByRole("table", { name: "MITRE ATT&CK techniques" }).waitFor();
      await shot("mitre");
      await page.goto("/mitre/T1566");
      await page.getByTestId("record-title").waitFor();
      await shot("mitre-technique");

      await page.goto("/indicators?q=198.51.100.23");
      await page.getByRole("link", { name: "198.51.100.23", exact: true }).first().click();
      await page.getByTestId("indicator-value").waitFor();
      await page.getByRole("button", { name: "Edit links" }).click();
      await page.getByRole("form", { name: "Edit linked intelligence" }).waitFor();
      await shot("indicator-links-editor");

      await page.goto("/dashboard");
      await page.getByRole("combobox", { name: "Search ArcRadar" }).fill("harbor");
      await page.getByRole("listbox").waitFor();
      await page.getByRole("group", { name: "Threat actors" }).waitFor();
      await shot("global-search-threat-intel", false);
      await context.close();
    });

    test(`reports and admin pages, ${theme}, ${size}`, async ({ browser, baseURL }) => {
      const { context, page } = await open(browser, baseURL!, size, theme, STORAGE.admin);
      const shot = async (name: string, fullPage = true) => {
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${DIR}/${name}-${theme}-${size}.png`, fullPage });
      };

      await page.goto("/reports");
      await page.getByRole("heading", { level: 1, name: "Reports" }).waitFor();
      await shot("reports");

      await page.goto("/reports/new");
      await page.getByRole("form", { name: "New report" }).waitFor();
      await shot("report-new");

      await page.goto("/reports/new");
      await page.getByLabel("Type").selectOption("vulnerabilities");
      await page.getByRole("button", { name: "Generate report" }).click();
      await page.getByTestId("report-title").waitFor();
      await shot("report-detail");
      const reportId = page.url().split("/").pop();

      // Its title is generated, not marker-named, so clean it up here, even if a later step fails.
      try {
        await page.goto("/api-keys");
        await page.getByRole("heading", { level: 1, name: "API keys" }).waitFor();
        await shot("api-keys");
        await page.getByRole("button", { name: "New key" }).click();
        await page.getByRole("dialog").waitFor();
        await shot("api-key-new-dialog", false);
        await page.keyboard.press("Escape");

        await page.goto("/integrations");
        await page.getByRole("heading", { level: 1, name: "Integrations" }).waitFor();
        await shot("integrations");

        await page.goto("/audit-log");
        await page.getByRole("heading", { level: 1, name: "Audit log" }).waitFor();
        await shot("audit-log");

        await page.goto("/settings");
        await page.getByRole("heading", { level: 1, name: "Settings" }).waitFor();
        await shot("settings");

        await page.goto("/profile");
        await page.getByRole("heading", { level: 1, name: "Profile" }).waitFor();
        await shot("profile");
      } finally {
        await adminFetch(`/rest/v1/reports?id=eq.${reportId}`, {
          method: "DELETE",
          headers: { prefer: "return=minimal" },
        });
        await context.close();
      }
    });
  }
}
