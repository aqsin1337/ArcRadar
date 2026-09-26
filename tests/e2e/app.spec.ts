import { expect, test } from "@playwright/test";
import { adminFetch, DEMO_PASSWORD, STORAGE } from "./support";

test.describe("viewer", () => {
  test.use({ storageState: STORAGE.viewer });

  test("sees the shell with a read-only role and only the navigation they may use", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveTitle("Overview · ArcRadar");

    await expect(page.getByTestId("user-role")).toHaveText("Viewer");
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link", { name: "Overview" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    // Viewers may read alerts, but the page is not built yet: shown as "Soon", not as a link.
    await expect(nav.getByText("Alerts")).toBeVisible();
    await expect(nav.getByRole("link", { name: "Alerts" })).toHaveCount(0);
    // Admin-only entries are not even shown.
    for (const hidden of ["Audit log", "Settings", "Integrations", "API keys"]) {
      await expect(nav.getByText(hidden, { exact: true }), hidden).toHaveCount(0);
    }
  });

  test("the overview explains the account's access and where data comes from", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByTestId("access-role")).toHaveText("Viewer");
    const main = page.getByRole("main");
    await expect(main.getByText("Indicators", { exact: true })).toBeVisible();
    await expect(main.getByText("read", { exact: true }).first()).toBeVisible();
    // The provenance legend shows all three origins, demo clearly marked.
    for (const label of ["Demo data", "Local", "External provider"]) {
      await expect(main.getByText(label, { exact: true }).first()).toBeVisible();
    }
    await expect(main.getByText(/Nothing on this page is sample data/)).toBeVisible();
  });

  test("has landmarks and headings a screen reader can navigate", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("main")).toHaveCount(1);
    await expect(page.getByRole("banner")).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter"); // activate the skip link
    await expect(page.getByRole("main")).toBeFocused();
  });

  test("already signed in, the auth pages forward to the overview", async ({ page }) => {
    for (const path of ["/login", "/signup", "/forgot-password"]) {
      await page.goto(path);
      await expect(page, path).toHaveURL(/\/dashboard$/);
    }
    await page.goto("/");
    await expect(page).toHaveURL(/\/dashboard$/);
  });

  test("an unknown page shows the not-found state with a way back", async ({ page }) => {
    await page.goto("/definitely-not-a-page");
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
    await page.getByRole("link", { name: "Back to ArcRadar" }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
  });

  test("the audit log API is off limits, and the API answers 403 not a redirect", async ({
    request,
  }) => {
    const response = await request.get("/api/audit-logs", { maxRedirects: 0 });
    expect(response.status()).toBe(403);
  });

  test("the theme toggle works inside the app shell", async ({ page }) => {
    await page.goto("/dashboard");
    await page.getByRole("button", { name: "Switch to light theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.getByRole("button", { name: "Switch to dark theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });
});

test.describe("admin", () => {
  test.use({ storageState: STORAGE.admin });

  test("sees the administration entries their role allows", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByTestId("user-role")).toHaveText("Admin");
    const nav = page.getByRole("navigation", { name: "Main" });
    for (const label of ["Audit log", "Settings", "Integrations", "API keys", "Administration"]) {
      await expect(nav.getByText(label, { exact: true }), label).toBeVisible();
    }
  });
});

test.describe("accounts that cannot use the app", () => {
  test("a disabled account is locked out at once, even with a live session", async ({
    browser,
  }) => {
    const email = `e2e-${Date.now()}@arcradar.test`;
    const created = await adminFetch("/auth/v1/admin/users", {
      method: "POST",
      body: JSON.stringify({ email, password: DEMO_PASSWORD, email_confirm: true }),
    });
    expect(created.status).toBe(200);
    const { id } = await created.json();

    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto("/login");
      await page.getByLabel("Email").fill(email);
      await page.getByLabel(/^Password/).fill(DEMO_PASSWORD);
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.getByTestId("user-role")).toHaveText("Viewer"); // new accounts are viewers

      const disable = await adminFetch(`/rest/v1/profiles?id=eq.${id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: false }),
        headers: { prefer: "return=minimal" },
      });
      expect(disable.status).toBe(204);

      await page.reload();
      await expect(page.getByRole("heading", { name: "This account has no access" })).toBeVisible();
      await expect(page.getByRole("navigation", { name: "Main" })).toHaveCount(0);

      // The way out still works.
      await page.getByRole("button", { name: "Sign out" }).click();
      await expect(page).toHaveURL(/\/login$/);
      await context.close();
    } finally {
      await adminFetch(`/auth/v1/admin/users/${id}`, { method: "DELETE" });
    }
  });
});
