import { expect, test } from "@playwright/test";
import { adminFetch, STORAGE } from "./support";

const marker = `E2E-MX-${Date.now()}`;
const alertTitle = `${marker} password spraying`;

test.beforeAll(async () => {
  // The catalog this test reads. A local database only has the few techniques the demo seed carries
  // (npm run import:mitre loads the whole catalog), so make sure the ones used here exist. Reference
  // data, left in place afterwards.
  const techniques = [
    ["T1566", "Phishing", ["Initial Access"]],
    ["T1059", "Command and Scripting Interpreter", ["Execution"]],
    ["T1110", "Brute Force", ["Credential Access"]],
    ["T1110.001", "Password Guessing", ["Credential Access"]],
    ["T1110.003", "Password Spraying", ["Credential Access"]],
    ["T1003", "OS Credential Dumping", ["Credential Access"]],
    ["T1486", "Data Encrypted for Impact", ["Impact"]],
  ] as const;
  const catalog = await adminFetch("/rest/v1/mitre_techniques?on_conflict=id", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      prefer: "resolution=merge-duplicates,return=minimal",
    },
    body: JSON.stringify(
      techniques.map(([id, name, tactics]) => ({
        id,
        name,
        tactics,
        url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
      })),
    ),
  });
  expect(catalog.status).toBeLessThan(300);

  // One alert that names a sub-technique (T1110.003, password spraying), the way a sensor's rule
  // mapping would. Written with the service role, like ingestion, and removed afterwards.
  const created = await adminFetch("/rest/v1/alerts", {
    method: "POST",
    headers: { "content-type": "application/json", prefer: "return=minimal" },
    body: JSON.stringify({
      title: alertTitle,
      severity: "high",
      source: marker,
      status: "new",
      origin: "external",
      technique_ids: ["T1110.003"],
    }),
  });
  expect(created.status).toBeLessThan(300);
});

test.afterAll(async () => {
  await adminFetch(`/rest/v1/alerts?source=eq.${marker}`, {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
});

test.describe("MITRE ATT&CK matrix", () => {
  test.use({ storageState: STORAGE.viewer });

  test("lays techniques out by tactic and colors the ones an alert named", async ({ page }) => {
    await page.goto("/mitre");
    await expect(page.getByRole("heading", { level: 1, name: "MITRE ATT&CK" })).toBeVisible();

    // Columns run in the order of an attack.
    const headings = await page
      .getByRole("region", { name: /ATT&CK matrix/ })
      .getByRole("heading", { level: 2 })
      .allTextContents();
    const names = headings.map((text) => text.replace(/\d+ techniques?.*$/, "").trim());
    expect(names.indexOf("Initial Access")).toBeLessThan(names.indexOf("Execution"));
    expect(names.indexOf("Execution")).toBeLessThan(names.indexOf("Credential Access"));
    expect(names.indexOf("Credential Access")).toBeLessThan(names.indexOf("Impact"));

    // The parent of the technique the alert names is highlighted, with its alert count.
    const credentialAccess = page.getByRole("list", { name: "Credential Access techniques" });
    const brute = credentialAccess.getByRole("link", { name: /T1110 Brute Force/ });
    await expect(brute).toHaveAttribute("data-observed", "true");
    await expect(brute).toContainText(/seen in \d+ alerts?/);
    // A technique nothing pointed at is plain, and opens its reference page.
    const other = credentialAccess.getByRole("link", { name: /T1003 OS Credential Dumping/ });
    await expect(other).toHaveAttribute("data-observed", "false");
    await expect(other).toHaveAttribute("href", "/mitre/T1003");
  });

  test("a click on a seen technique opens the alerts that name it", async ({ page }) => {
    await page.goto("/mitre");
    await page
      .getByRole("list", { name: "Credential Access techniques" })
      .getByRole("link", { name: /T1110 Brute Force/ })
      .click();

    await expect(page).toHaveURL(/\/alerts\?technique=T1110$/);
    await expect(page.getByText(/Showing the alerts that name ATT&CK technique/)).toBeVisible();
    await expect(page.getByRole("link", { name: alertTitle })).toBeVisible();

    await page.getByRole("link", { name: "Clear this filter" }).click();
    await expect(page).toHaveURL(/\/alerts$/);
  });

  test("sub-techniques and the seen-only view are switches in the address", async ({ page }) => {
    await page.goto("/mitre?sub=1");
    const credentialAccess = page.getByRole("list", { name: "Credential Access techniques" });
    await expect(
      credentialAccess.getByRole("link", { name: /T1110\.003 Password Spraying/ }),
    ).toHaveAttribute("data-observed", "true");
    await expect(
      credentialAccess.getByRole("link", { name: /T1110\.001 Password Guessing/ }),
    ).toHaveAttribute("data-observed", "false");

    await page.getByRole("link", { name: "Only what was seen" }).click();
    await expect(page).toHaveURL(/observed=1/);
    await expect(page).toHaveURL(/sub=1/);
    // Nothing that no alert named is left; the columns with nothing in them are gone.
    await expect(
      page.locator('a[data-observed="false"]').filter({ hasText: /T1110\.003/ }),
    ).toHaveCount(0);
    await expect(page.getByRole("list", { name: "Initial Access techniques" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: /T1110\.003 Password Spraying/ })).toBeVisible();
  });

  test("a technique page lists the alerts that name it and links to each", async ({ page }) => {
    await page.goto("/mitre/T1110");
    await expect(page.getByTestId("record-title")).toContainText("T1110 Brute Force");
    await expect(page.getByText(/Named by \d+ alerts?/)).toBeVisible();
    await page.getByRole("link", { name: alertTitle }).click();
    await expect(page).toHaveURL(/\/alerts\/[0-9a-f-]{36}$/);

    await page.goto("/mitre/T1110.003");
    await expect(page.getByRole("link", { name: "T1110", exact: true })).toBeVisible(); // its parent

    await page.goto("/mitre/T9");
    await expect(page.getByText(/not found|could not be found/i).first()).toBeVisible();
  });

  test("the overview counts it among the most seen techniques", async ({ page }) => {
    await page.goto("/dashboard");
    const panel = page.locator("section", { hasText: "Most seen ATT&CK techniques" });
    await expect(panel.getByRole("link", { name: /T1110 Brute Force/ })).toBeVisible();
  });
});
