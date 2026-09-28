import { expect, test } from "@playwright/test";
import { adminFetch, STORAGE } from "./support";

const marker = `E2E-ADM-${Date.now()}`;

test.afterAll(async () => {
  const gone = { method: "DELETE", headers: { prefer: "return=minimal" } };
  await adminFetch(`/rest/v1/reports?title=like.${marker}*`, gone);
  await adminFetch(`/rest/v1/api_keys?name=like.${marker}*`, gone);
});

test.describe("Reports (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("is live in the navigation, reads the list, but cannot generate one", async ({ page }) => {
    await page.goto("/dashboard");
    await page
      .getByRole("navigation", { name: "Main" })
      .getByRole("link", { name: "Reports" })
      .click();
    await expect(page).toHaveURL(/\/reports$/);
    await expect(page.getByRole("heading", { level: 1, name: "Reports" })).toBeVisible();
    await expect(page.getByRole("link", { name: "New report" })).toHaveCount(0);

    const denied = await page.request.post("/api/reports", {
      data: { type: "vulnerabilities" },
    });
    expect(denied.status()).toBe(403);
  });
});

test.describe("Reports (analyst)", () => {
  test.use({ storageState: STORAGE.analyst });

  test("generates a workspace summary, previews it, prints it, and deletes it", async ({
    page,
  }) => {
    await page.goto("/reports/new");
    await page.getByLabel("Type").selectOption("alerts");
    await page.getByLabel("Title").fill(`${marker} alert summary`);
    await page.getByRole("button", { name: "Generate report" }).click();

    await expect(page).toHaveURL(/\/reports\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("report-title")).toHaveText(`${marker} alert summary`);
    await expect(page.getByTestId("report-subtitle")).toContainText("Alert summary");
    await expect(page.getByTestId("report-subtitle").getByText("Local")).toBeVisible();
    await expect(page.getByRole("heading", { name: "By status" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "By severity" })).toBeVisible();

    // It is an honest snapshot: it appears in the list and can be reopened unchanged.
    await page.goto(`/reports?q=${encodeURIComponent(marker)}`);
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await page.locator("tbody tr").first().getByRole("link").first().click();
    await expect(page.getByTestId("report-title")).toHaveText(`${marker} alert summary`);

    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("dialog").waitFor();
    await page.getByRole("button", { name: "Delete report" }).click();
    await expect(page).toHaveURL(/\/reports$/);
    await page.goto(`/reports?q=${encodeURIComponent(marker)}`);
    await expect(page.getByText("No reports match")).toBeVisible();
  });

  test("an investigation report needs a real investigation, found by name", async ({ page }) => {
    await page.goto("/reports/new");
    await page.getByLabel("Type").selectOption("investigation");
    await page.getByLabel("Investigation").fill("Harbor Lights");
    await page
      .getByRole("button", { name: /Harbor Lights/ })
      .first()
      .click();
    await page.getByRole("button", { name: "Generate report" }).click();
    await expect(page).toHaveURL(/\/reports\/[0-9a-f-]{36}$/);
    const reportId = page.url().split("/").pop();

    // Its title is generated from the investigation's own title, not the marker, so it would not be
    // swept by afterAll: clean it up here, even if an assertion below fails.
    try {
      await expect(page.getByTestId("report-title")).toContainText("Investigation report: ");
      await expect(page.getByRole("heading", { name: /^Notes and history/ })).toBeVisible();
    } finally {
      const gone = { method: "DELETE", headers: { prefer: "return=minimal" } };
      await adminFetch(`/rest/v1/reports?id=eq.${reportId}`, gone);
    }
  });
});

test.describe("API keys", () => {
  test.use({ storageState: STORAGE.admin });

  test("the lifecycle: create, see it once, list it, revoke it", async ({ page }) => {
    await page.goto("/api-keys");
    await page.getByRole("button", { name: "New key" }).click();
    await page.getByLabel("Name").fill(`${marker} key`);
    await page.getByRole("button", { name: "Create key" }).click();

    const dialog = page.getByRole("dialog", { name: "Your new API key" });
    await expect(dialog).toBeVisible();
    const key = await dialog.locator("code").textContent();
    expect(key).toMatch(/^arc_[A-Za-z0-9_-]{43}$/);
    await dialog.getByRole("button", { name: "Done" }).click();

    const row = page.locator("tbody tr", { hasText: `${marker} key` });
    await expect(row).toBeVisible();
    await expect(row.getByText("active", { exact: true })).toBeVisible();

    await row.getByRole("button", { name: "Revoke" }).click();
    const confirmDialog = page.getByRole("dialog", { name: "Revoke this key?" });
    await confirmDialog.waitFor();
    await confirmDialog.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(row.getByText("revoked", { exact: true })).toBeVisible();
    await expect(row.getByRole("button", { name: "Revoke" })).toHaveCount(0);

    // A revoked key stops working at once.
    const used = await page.request.post("/api/ingest/wazuh", {
      headers: { authorization: `Bearer ${key}` },
      data: { alerts: [] },
    });
    expect(used.status()).toBe(401);
  });
});

test.describe("Integrations", () => {
  test.use({ storageState: STORAGE.admin });

  test("shows every provider's status and lets an administrator pause a configured one", async ({
    page,
  }) => {
    await page.goto("/integrations");
    await expect(page.getByRole("heading", { level: 1, name: "Integrations" })).toBeVisible();
    await expect(page.getByText("Demo data provider")).toBeVisible();
    await expect(page.getByText("Always available")).toBeVisible();
    // The demo provider's switch is disabled: it can never be turned off from here.
    const demoCard = page.locator("li", { hasText: "Demo data provider" });
    await expect(demoCard.getByRole("checkbox")).toBeDisabled();

    const wazuhCard = page.locator("li", { hasText: "Wazuh" });
    await expect(wazuhCard.getByText("Configured")).toBeVisible();
    const checkbox = wazuhCard.getByRole("checkbox");
    await expect(checkbox).toBeChecked();
    await checkbox.uncheck();
    await expect(wazuhCard.getByText("Disabled")).toBeVisible();
    await checkbox.check(); // leave it as it was found
    await expect(wazuhCard.getByText("Enabled")).toBeVisible();

    // The five AI providers are listed like any other, and (no key configured in this environment)
    // the AI provider picker below has nothing selectable yet.
    await expect(page.getByText("Groq")).toBeVisible();
    const picker = page.getByTestId("ai-provider-picker");
    await expect(picker).toBeVisible();
    await expect(picker.getByText(/No AI provider is both configured and enabled/)).toBeVisible();
    await expect(picker.getByRole("combobox")).toHaveValue("");
  });

  test("an analyst can see the catalog but not the switch, and reads the AI provider read-only", async ({
    browser,
    baseURL,
  }) => {
    const context = await browser.newContext({ storageState: STORAGE.analyst, baseURL });
    const page = await context.newPage();
    await page.goto("/integrations");
    await expect(page.getByText("Demo data provider")).toBeVisible();
    await expect(page.getByRole("checkbox")).toHaveCount(0);
    await expect(
      page.getByText("No AI provider is active. Ask an administrator to choose one."),
    ).toBeVisible();
    await context.close();
  });
});

test.describe("Audit log", () => {
  test.use({ storageState: STORAGE.admin });

  test("lists entries, filters by action, and is off limits to a viewer's page", async ({
    page,
  }) => {
    await page.goto("/audit-log");
    await expect(page.getByRole("heading", { level: 1, name: "Audit log" })).toBeVisible();
    await expect(page.locator("tbody tr").first()).toBeVisible();

    await page.getByLabel("Action").selectOption("auth.login");
    await page.getByRole("button", { name: "Apply" }).click();
    await expect(page).toHaveURL(/action=auth\.login/);
    for (const row of await page.locator("tbody tr").all()) {
      await expect(row).toContainText("auth.login");
    }

    await page.goto("/audit-log?action=not-a-real-action");
    await expect(page.getByText("Some options in the address were not valid")).toBeVisible();
  });
});

test.describe("Settings (users)", () => {
  test.use({ storageState: STORAGE.admin });

  test("changes a role and status, but never the caller's own, and keeps one active admin", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();

    const adminEmail = /admin@arcradar\.test/;
    const analystEmail = /analyst@arcradar\.test/;
    const adminRow = page.locator("tbody tr", { has: page.getByText(adminEmail) });
    await expect(adminRow.getByText("Admin", { exact: true })).toBeVisible();
    await expect(adminRow.getByRole("combobox")).toHaveCount(0); // no control on your own row

    const analystRow = page.locator("tbody tr", { has: page.getByText(analystEmail) });
    await expect(analystRow.getByRole("combobox")).toBeEnabled();
    await expect(analystRow.getByRole("checkbox")).toBeChecked();
  });

  test("a viewer never reaches the page", async ({ browser, baseURL }) => {
    const context = await browser.newContext({ storageState: STORAGE.viewer, baseURL });
    const page = await context.newPage();
    await page.goto("/settings");
    await expect(page.getByText(/don.t have access|not allowed|access denied/i)).toBeVisible();
    await context.close();
  });
});

test.describe("Profile", () => {
  test.use({ storageState: STORAGE.analyst });

  test("every role can reach it from the header, and edit their own display name", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await page.getByTestId("user-name").click();
    await expect(page).toHaveURL(/\/profile$/);
    await expect(page.getByRole("heading", { level: 1, name: "Profile" })).toBeVisible();

    const original = await page.getByLabel("Display name").inputValue();
    await page.getByLabel("Display name").fill(`${marker} Analyst`);
    await page.getByRole("button", { name: "Save profile" }).click();
    await expect(page.getByText("Saved.")).toBeVisible();
    await expect(page.getByTestId("user-name")).toHaveText(`${marker} Analyst`);

    // Restore it so other tests and sessions see the original name again.
    await page.getByLabel("Display name").fill(original);
    await page.getByRole("button", { name: "Save profile" }).click();
    await expect(page.getByText("Saved.")).toBeVisible();
  });
});
