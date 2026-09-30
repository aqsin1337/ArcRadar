import { expect, test, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { adminFetch, cleanTelemetry, ingest, STORAGE, wazuhAlerts } from "./support";

// Runs in a phone-sized viewport (Pixel 5, 393px wide).
async function hasHorizontalScroll(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
}

test.describe("signed out", () => {
  test("the sign-in page fits a phone: no sideways scroll, brand panel hidden", async ({
    page,
  }) => {
    await page.goto("/login");
    expect(await hasHorizontalScroll(page)).toBe(false);
    await expect(page.getByText("Know what is on your radar.")).toBeHidden();
    await expect(page.getByLabel("Email")).toBeVisible();
    // Tap targets are large enough to hit.
    const box = await page.getByRole("button", { name: "Sign in" }).boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(40);
  });

  test("the sign-up page fits a phone", async ({ page }) => {
    await page.goto("/signup");
    expect(await hasHorizontalScroll(page)).toBe(false);
  });
});

test.describe("signed in", () => {
  test.use({ storageState: STORAGE.admin });

  test("the sidebar becomes a slide-over that opens, traps focus and closes with Escape", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    expect(await hasHorizontalScroll(page)).toBe(false);

    // No permanent sidebar on a phone.
    const menu = page.getByRole("button", { name: "Open navigation" });
    await expect(menu).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main" })).toBeHidden();

    await menu.click();
    const drawer = page.getByRole("dialog", { name: "Navigation" });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole("navigation", { name: "Main" })).toBeVisible();
    await expect(drawer.getByText("Audit log")).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
  });

  test("the drawer also closes when the backdrop is tapped", async ({ page }) => {
    await page.goto("/dashboard");
    await page.getByRole("button", { name: "Open navigation" }).click();
    const drawer = page.getByRole("dialog", { name: "Navigation" });
    await expect(drawer).toBeVisible();
    await page.mouse.click(380, 400); // outside the 288px-wide panel
    await expect(drawer).toBeHidden();
  });

  test("the overview cards stack without overflowing", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
    // The role badge is hidden on phones to leave room for search; sign-out stays reachable.
    await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
    await expect(page.getByTestId("user-role")).toBeHidden();
  });

  test("the indicator list fits a phone and keeps the provenance label in view", async ({
    page,
  }) => {
    await page.goto("/indicators");
    await expect(page.locator("tbody tr").first()).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);

    // The columns collapse into the first cell, so nothing hides behind a sideways scroll.
    const table = page.getByRole("region", { name: "Indicators" });
    expect(await table.evaluate((element) => element.scrollWidth > element.clientWidth + 1)).toBe(
      false,
    );
    const origin = page
      .locator("tbody tr")
      .first()
      .getByText("Demo data")
      .filter({ visible: true });
    await origin.scrollIntoViewIfNeeded(); // the filters fill the first screen; scroll down, not sideways
    await expect(origin).toBeInViewport();
    await expect(
      page.locator("tbody tr").first().getByText("Malicious").filter({ visible: true }),
    ).toBeInViewport();

    // The column headers are gone, so sorting is offered as a menu instead.
    await page.getByRole("combobox", { name: "Sort by" }).selectOption("severity");
    await expect(page).toHaveURL(/sort=severity/);
  });

  test("the filters are usable on a phone", async ({ page }) => {
    await page.goto("/indicators");
    await page.getByRole("combobox", { name: "Verdict", exact: true }).selectOption("malicious");
    await expect(page).toHaveURL(/verdict=malicious/);
    await page.getByRole("searchbox", { name: "Search indicators" }).fill("harbor");
    await expect(page).toHaveURL(/q=harbor/);
    await expect(page.locator("tbody tr").first()).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  test("long values and the forms fit a phone", async ({ page }) => {
    await page.goto("/indicators?q=verify%3Fsession");
    await page.getByRole("cell").getByRole("link").first().click();
    await expect(page.getByTestId("indicator-value")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);

    await page.goto("/indicators/new");
    await expect(page.getByRole("form", { name: "New indicator" })).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  test("the lookup pages fit a phone, with long values wrapped and the demo label in view", async ({
    page,
  }) => {
    const sha256 = createHash("sha256").update("arcradar-demo-sample-1", "utf8").digest("hex");
    const url = "https://login-secure-update.example/account/verify?session=demo";
    for (const path of [
      "/intelligence/ip?q=198.51.100.23",
      "/intelligence/domain?q=harbor-lights-c2.example",
      `/intelligence/url?q=${encodeURIComponent(url)}`,
      `/intelligence/hash?q=${sha256}`,
      "/intelligence/ip?q=203.0.113.190",
    ]) {
      await page.goto(path);
      await expect(page.getByTestId("intel-result")).toBeVisible();
      expect(await hasHorizontalScroll(page), path).toBe(false);
    }

    await page.goto("/intelligence/ip?q=198.51.100.23");
    await expect(page.getByRole("status").filter({ hasText: "Demo data" })).toBeInViewport();
    const button = await page.getByRole("button", { name: "Look up" }).boundingBox();
    expect(button!.height).toBeGreaterThanOrEqual(40);
  });

  test("the vulnerability list and a CVE page fit a phone, provenance included", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities");
    await expect(page.locator("tbody tr").first()).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);

    const table = page.getByRole("region", { name: "Vulnerabilities" });
    expect(await table.evaluate((element) => element.scrollWidth > element.clientWidth + 1)).toBe(
      false,
    );
    const origin = page
      .locator("tbody tr")
      .first()
      .getByText("Demo data")
      .filter({ visible: true });
    await origin.scrollIntoViewIfNeeded();
    await expect(origin).toBeInViewport();
    await expect(
      page.locator("tbody tr").first().getByText("Exploited in the wild").filter({ visible: true }),
    ).toBeInViewport();

    // The statistics tiles filter, and sorting is a menu once the column headers are gone.
    await page
      .getByRole("region", { name: "Vulnerability statistics" })
      .getByRole("link", { name: /Critical/ })
      .click();
    await expect(page).toHaveURL(/severity=critical/);
    await page.getByRole("combobox", { name: "Sort by" }).selectOption("cvss_score");
    await expect(page).toHaveURL(/sort=cvss_score/);

    await page.goto("/vulnerabilities/CVE-2021-44228");
    await expect(page.getByTestId("vulnerability-id")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  test("global search results open inside the phone screen", async ({ page }) => {
    await page.goto("/dashboard");
    await page.getByRole("combobox", { name: "Search ArcRadar" }).fill("harbor");
    const listbox = page.getByRole("listbox", { name: "Search results" });
    await expect(listbox.getByRole("option").first()).toBeVisible();
    const box = await listbox.boundingBox();
    const viewport = page.viewportSize()!;
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  /** A list whose table keeps the record's provenance in view on a phone, with no sideways scroll. */
  async function expectListFitsPhone(page: Page, path: string, table: string) {
    await page.goto(path);
    await expect(page.locator("tbody tr").first()).toBeVisible();
    expect(await hasHorizontalScroll(page), path).toBe(false);
    const region = page.getByRole("region", { name: table });
    expect(
      await region.evaluate((element) => element.scrollWidth > element.clientWidth + 1),
      `${path} table`,
    ).toBe(false);
    // (Exact: some descriptions in the rows begin with the words "Demo data.")
    const origin = page
      .locator("tbody tr")
      .first()
      .getByText("Demo data", { exact: true })
      .filter({ visible: true });
    await origin.scrollIntoViewIfNeeded(); // the filters fill the first screen; scroll down, not sideways
    await expect(origin, path).toBeInViewport();
  }

  test("the alert list and an alert fit a phone, provenance and workflow included", async ({
    page,
  }) => {
    await expectListFitsPhone(page, "/alerts", "Alerts");
    // The statistics tiles filter, and sorting is a menu once the column headers are gone.
    await page
      .getByRole("region", { name: "Alert statistics" })
      .getByRole("link", { name: /^New\b/ })
      .click();
    await expect(page).toHaveURL(/status=new/);
    await page.getByRole("combobox", { name: "Sort by" }).selectOption("severity");
    await expect(page).toHaveURL(/sort=severity/);

    await page.goto("/alerts?q=beacon");
    await page.locator("tbody tr").first().getByRole("link").first().click();
    await expect(page.getByTestId("alert-title")).toBeVisible();
    await expect(page.getByTestId("alert-actions")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
    const buttons = page.getByTestId("alert-actions").getByRole("button");
    for (const button of await buttons.all()) {
      const box = await button.boundingBox();
      expect(box!.height).toBeGreaterThanOrEqual(32);
    }
  });

  test("the investigation list and an investigation fit a phone", async ({ page }) => {
    await expectListFitsPhone(page, "/investigations", "Investigations");

    await page.goto("/investigations?q=Harbor%20Lights%20C2");
    await page.locator("tbody tr").first().getByRole("link").first().click();
    await expect(page.getByTestId("investigation-title")).toBeVisible();
    await expect(page.getByTestId("investigation-controls")).toBeVisible();
    await expect(page.getByLabel("Add a note")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  test("the telemetry page and a sensor alert fit a phone, sensor status and asset included", async ({
    page,
  }) => {
    const marker = `E2E-TELM-${Date.now()}`;
    try {
      const created = await page.request.post("/api/api-keys", {
        data: { name: `${marker} key`, scopes: ["ingest:wazuh"], expires_in_days: 1 },
      });
      expect(created.status()).toBe(201);
      const { key } = (await created.json()).data as { key: string };
      expect((await ingest(key, wazuhAlerts(marker))).status).toBe(200);

      await page.goto("/telemetry");
      await expect(page.getByRole("heading", { level: 1, name: "Telemetry" })).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
      // Each source card keeps its status and its provenance label inside the phone screen.
      const wazuh = page.locator('[data-testid="source-card"][data-source="wazuh"]');
      await wazuh.scrollIntoViewIfNeeded();
      await expect(wazuh.getByText("Receiving")).toBeInViewport();
      await expect(wazuh.getByText("External provider")).toBeInViewport();
      const demo = page.locator('[data-testid="source-card"][data-status="demo"]').first();
      await demo.scrollIntoViewIfNeeded();
      await expect(demo.getByText("Demo data")).toBeInViewport();

      for (const name of ["Assets", "Events"]) {
        const region = page.getByRole("region", { name, exact: true });
        await region.scrollIntoViewIfNeeded();
        expect(
          await region.evaluate((element) => element.scrollWidth > element.clientWidth + 1),
          `${name} table`,
        ).toBe(false);
      }
      const asset = page.getByRole("region", { name: "Assets" }).locator("tbody tr", {
        hasText: `${marker}-WIN10`,
      });
      await asset.scrollIntoViewIfNeeded();
      await expect(asset.getByText("External provider").filter({ visible: true })).toBeInViewport();

      // Events are filtered and sorted with menus, as in the other lists.
      await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("wazuh");
      await expect(page).toHaveURL(/source=wazuh/);
      await page.getByRole("combobox", { name: "Sort by" }).selectOption("severity");
      await expect(page).toHaveURL(/sort=severity/);
      expect(await hasHorizontalScroll(page)).toBe(false);

      await page.goto(`/alerts?q=${encodeURIComponent(`${marker} multiple`)}`);
      await page.locator("tbody tr").first().getByRole("link").first().click();
      await expect(page.getByTestId("alert-title")).toBeVisible();
      await expect(page.getByTestId("alert-asset")).toContainText(`${marker}-WIN10`);
      await expect(page.getByRole("list", { name: "ATT&CK techniques" })).toBeVisible();
      await expect(page.getByText("External provider").first()).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
    } finally {
      await cleanTelemetry(marker);
    }
  });

  test("the ATT&CK matrix scrolls inside itself and its pages fit a phone", async ({ page }) => {
    await page.goto("/mitre");
    await expect(page.getByRole("region", { name: /ATT&CK matrix/ })).toBeVisible();
    // 14 columns do not fit a phone: the matrix scrolls sideways inside its own box, the page does not.
    expect(await hasHorizontalScroll(page)).toBe(false);
    await page.goto("/mitre?sub=1");
    expect(await hasHorizontalScroll(page)).toBe(false);
    await page.goto("/mitre/T1566");
    await expect(page.getByTestId("record-title")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
  });

  test("the create forms for alerts and investigations fit a phone", async ({ page }) => {
    for (const [path, name] of [
      ["/alerts/new", "New alert"],
      ["/investigations/new", "New investigation"],
    ] as const) {
      await page.goto(path);
      await expect(page.getByRole("form", { name })).toBeVisible();
      expect(await hasHorizontalScroll(page), path).toBe(false);
    }
  });

  test("the dashboard, reports and admin pages fit a phone", async ({ page }) => {
    await page.goto("/dashboard");
    expect(await hasHorizontalScroll(page)).toBe(false);
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(page.getByText("Total indicators")).toBeVisible();

    // Reports has no seed data, so an admin generates one to check a real row, not just the empty state.
    await page.goto("/reports/new");
    await expect(page.getByRole("form", { name: "New report" })).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
    await page.getByLabel("Type").selectOption("vulnerabilities");
    await page.getByRole("button", { name: "Generate report" }).click();
    await expect(page.getByTestId("report-title")).toBeVisible();
    expect(await hasHorizontalScroll(page)).toBe(false);
    const reportId = page.url().split("/").pop();

    // Its title is generated, not marker-named, so clean it up here, even if a later step fails.
    try {
      await page.goto("/reports");
      await expect(page.locator("tbody tr").first()).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
      const reportsTable = page.getByRole("region", { name: "Reports" });
      expect(
        await reportsTable.evaluate((element) => element.scrollWidth > element.clientWidth + 1),
      ).toBe(false);

      await page.goto("/api-keys");
      await expect(page.getByRole("heading", { level: 1, name: "API keys" })).toBeVisible();
      await page.getByRole("button", { name: "New key" }).click();
      await expect(page.getByRole("dialog")).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
      await page.keyboard.press("Escape");

      await page.goto("/integrations");
      await expect(page.getByText("Demo data provider")).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);

      await page.goto("/audit-log");
      await expect(page.locator("tbody tr").first()).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
      const auditTable = page.getByRole("region", { name: "Audit log" });
      expect(
        await auditTable.evaluate((element) => element.scrollWidth > element.clientWidth + 1),
      ).toBe(false);

      await page.goto("/settings");
      await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);

      await page.goto("/profile");
      await expect(page.getByRole("heading", { level: 1, name: "Profile" })).toBeVisible();
      expect(await hasHorizontalScroll(page)).toBe(false);
    } finally {
      await adminFetch(`/rest/v1/reports?id=eq.${reportId}`, {
        method: "DELETE",
        headers: { prefer: "return=minimal" },
      });
    }
  });
});
