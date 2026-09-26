import { expect, test } from "@playwright/test";
import { DEMO_PASSWORD } from "./support";

test.describe("signed-out visitor", () => {
  test("the root sends visitors to the sign-in page", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
    await expect(page).toHaveTitle("Sign in · ArcRadar");
  });

  test("a protected page redirects to sign-in and remembers where the visitor was going", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login\?next=%2Fdashboard$/);
  });

  test("unknown and recovery-only pages are protected too (deny by default)", async ({ page }) => {
    for (const path of ["/definitely-not-a-page", "/reset-password", "/alerts"]) {
      await page.goto(path);
      await expect(page, path).toHaveURL(/\/login\?next=/);
    }
  });

  test("API routes answer with JSON 401, not a redirect", async ({ request }) => {
    const response = await request.get("/api/auth/me", { maxRedirects: 0 });
    expect(response.status()).toBe(401);
    expect((await response.json()).error.code).toBe("UNAUTHENTICATED");
  });

  test("the form validates in the browser before calling the server", async ({ page }) => {
    const apiCalls: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("/api/auth/login")) apiCalls.push(request.url());
    });

    await page.goto("/login");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByText("Enter a valid email address.")).toBeVisible();
    await expect(page.getByText("Password is required.")).toBeVisible();
    await expect(page.getByLabel("Email")).toHaveAttribute("aria-invalid", "true");
    expect(apiCalls).toHaveLength(0);
  });

  test("a wrong password shows one generic message and keeps the visitor on the page", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.getByLabel("Email").fill("viewer@arcradar.test");
    await page.getByLabel(/^Password/).fill("Wrong-Password-1");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(
      page.getByRole("alert").filter({ hasText: "Invalid email or password." }),
    ).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
    // The form is usable again and the typed email is still there.
    await expect(page.getByRole("button", { name: "Sign in" })).toBeEnabled();
    await expect(page.getByLabel("Email")).toHaveValue("viewer@arcradar.test");
  });

  test("local demo accounts fill the form in one click (flag is on for the local stack)", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: "Analyst" }).click();
    await expect(page.getByLabel("Email")).toHaveValue("analyst@arcradar.test");
    await expect(page.getByLabel(/^Password/)).toHaveValue(DEMO_PASSWORD);
  });

  test("password visibility can be toggled with the keyboard-reachable button", async ({
    page,
  }) => {
    await page.goto("/login");
    const password = page.getByLabel(/^Password/);
    await expect(password).toHaveAttribute("type", "password");
    await page.getByRole("button", { name: "Show password" }).click();
    await expect(password).toHaveAttribute("type", "text");
    await expect(page.getByRole("button", { name: "Hide password" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  test("signing in lands on the overview, ignores an off-site next, then signing out returns to sign-in", async ({
    page,
  }) => {
    await page.goto("/login?next=//evil.example");
    await page.getByLabel("Email").fill("viewer@arcradar.test");
    await page.getByLabel(/^Password/).fill(DEMO_PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login$/);

    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login\?next=%2Fdashboard$/);
  });

  test("signing in returns to the page the visitor first asked for", async ({ page }) => {
    await page.goto("/login?next=%2Fdashboard");
    await page.getByLabel("Email").fill("viewer@arcradar.test");
    await page.getByLabel(/^Password/).fill(DEMO_PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login$/);
  });

  test("sign-up checks the password policy and confirmation without a server call", async ({
    page,
  }) => {
    const apiCalls: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("/api/auth/signup")) apiCalls.push(request.url());
    });

    await page.goto("/signup");
    await page.getByLabel("Email").fill("new.person@example.test");
    // Role-based: the requirements list carries an aria-label starting with "Password" too.
    await page.getByRole("textbox", { name: "Password", exact: true }).fill("Sh0rt");

    const rules = page.getByRole("list", { name: "Password requirements" });
    await expect(rules.getByText("At least 10 characters")).toContainText("(not met yet)");
    await expect(rules.getByText("A digit")).toContainText("(met)");

    await page.getByLabel("Confirm password").fill("Different1");
    await page.getByRole("button", { name: "Create account" }).click();

    await expect(page.getByText("Password must be at least 10 characters.")).toBeVisible();
    await expect(page.getByText("Passwords do not match.")).toBeVisible();
    expect(apiCalls).toHaveLength(0);
  });

  test("forgot-password confirms without revealing whether the account exists", async ({
    page,
  }) => {
    await page.goto("/forgot-password");
    await page.getByLabel("Email").fill("nobody-e2e@arcradar.test");
    await page.getByRole("button", { name: "Send reset link" }).click();
    await expect(page.getByText("Check your inbox")).toBeVisible();
    await expect(page.getByText(/If an account exists for/)).toBeVisible();
  });

  test("an invalid email link explains itself on the sign-in page", async ({ page }) => {
    await page.goto("/auth/callback?code=not-a-real-code");
    await expect(page).toHaveURL(/\/login\?error=invalid_link$/);
    await expect(page.getByRole("status")).toContainText("invalid or has expired");
  });

  test("the theme choice sticks across reloads and is set on the server (no flash)", async ({
    page,
  }) => {
    await page.goto("/login");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.getByRole("button", { name: "Switch to light theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

    // The raw HTML from the server (before any script runs) already carries the chosen theme.
    const html = await (await page.request.get("/login")).text();
    expect(html).toMatch(/<html[^>]*data-theme="light"/);
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("keyboard users get a skip link as the first focusable element", async ({ page }) => {
    // /signup has no autofocus (the sign-in and reset pages focus their first field).
    await page.goto("/signup");
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to main content" });
    await expect(skip).toBeFocused();
    await expect(skip).toBeInViewport();
  });

  test("the sign-in page has exactly one main landmark and one h1", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("main")).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
  });
});
