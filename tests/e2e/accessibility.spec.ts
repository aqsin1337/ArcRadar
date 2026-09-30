import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { STORAGE } from "./support";

// An axe-core pass over the app's shared UI surface: every list page (table, filters, badges,
// pagination), every create form, one representative detail page per record type, and the
// signed-out pages. `color-contrast` is disabled here on purpose: `npm run check:contrast`
// already checks every design-token pair in both themes directly against WCAG, so this spec is
// for what that script cannot see -- labels, roles, landmarks, names, and structure.

function summarize(
  violations: { id: string; impact?: string | null; nodes: { target: unknown[] }[] }[],
) {
  return violations
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)
    .join("\n");
}

async function expectClean(page: Page) {
  const { violations } = await new AxeBuilder({ page }).disableRules(["color-contrast"]).analyze();
  expect(violations, summarize(violations)).toEqual([]);
}

test.describe("signed out", () => {
  for (const path of ["/login", "/signup", "/forgot-password"]) {
    test(`${path} has no axe violations`, async ({ page }) => {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      await expectClean(page);
    });
  }
});

test.describe("signed in as admin", () => {
  test.use({ storageState: STORAGE.admin });

  const listPages = [
    "/dashboard",
    "/indicators",
    "/alerts",
    "/investigations",
    "/mitre",
    "/mitre?sub=1",
    "/mitre/T1110",
    "/vulnerabilities",
    "/telemetry",
    "/reports",
    "/api-keys",
    "/integrations",
    "/audit-log",
    "/settings",
    "/profile",
    "/detection-rules",
    "/response-actions",
  ];

  for (const path of listPages) {
    test(`${path} has no axe violations`, async ({ page }) => {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      await expectClean(page);
    });
  }

  test("the indicator creation form has no axe violations", async ({ page }) => {
    await page.goto("/indicators/new");
    await page.waitForLoadState("networkidle");
    await expectClean(page);
  });

  test("an indicator detail page has no axe violations", async ({ page }) => {
    await page.goto("/indicators");
    await page.getByRole("table").waitFor();
    await page.getByRole("row").nth(1).getByRole("link").first().click();
    await page.waitForLoadState("networkidle");
    await expectClean(page);
  });

  test("an alert detail page has no axe violations", async ({ page }) => {
    await page.goto("/alerts");
    await page.getByRole("table").waitFor();
    await page.getByRole("row").nth(1).getByRole("link").first().click();
    await page.waitForLoadState("networkidle");
    await expectClean(page);
  });

  test("the mobile drawer has no axe violations", async ({ page }) => {
    await page.setViewportSize({ width: 393, height: 852 });
    await page.goto("/dashboard");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Open navigation" }).click();
    await page.waitForTimeout(200);
    await expectClean(page);
  });
});
