import { test, type Browser } from "@playwright/test";
import { STORAGE } from "./support";

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
  }
}
