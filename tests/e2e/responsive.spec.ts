import { expect, test, type Page } from "@playwright/test";
import { STORAGE } from "./support";

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
});
