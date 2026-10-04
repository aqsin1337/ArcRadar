import { expect, test, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { STORAGE } from "./support";

const sample = (algorithm: "md5" | "sha1" | "sha256", n = 1) =>
  createHash(algorithm).update(`arcradar-demo-sample-${n}`, "utf8").digest("hex");

const rows = (page: Page) => page.locator("tbody tr");
const stats = (page: Page) => page.getByRole("region", { name: "Vulnerability statistics" });

test.describe("lookup pages (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("the four lookups are live in the navigation and start with samples", async ({ page }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    for (const [label, path, title] of [
      ["IP intelligence", "/intelligence/ip", "IP intelligence"],
      ["Domain intelligence", "/intelligence/domain", "Domain intelligence"],
      ["URL analysis", "/intelligence/url", "URL analysis"],
      ["Hash lookup", "/intelligence/hash", "Hash lookup"],
    ] as const) {
      await nav.getByRole("link", { name: label }).click();
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page).toHaveTitle(`${title} · ArcRadar`);
      await expect(nav.getByRole("link", { name: label })).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
      await expect(page.getByText("Try a sample from the demo dataset")).toBeVisible();
    }
  });

  test("an IP lookup shows demo data as demo, with the workspace context and a timeline", async ({
    page,
  }) => {
    await page.goto("/intelligence/ip");
    await page.getByRole("link", { name: "198.51.100.23" }).click();
    await expect(page).toHaveURL(/\/intelligence\/ip\?q=198\.51\.100\.23$/);

    await expect(page.getByTestId("intel-value")).toHaveText("198.51.100.23");
    // The provenance is impossible to miss: a banner, the provider label and the card note.
    await expect(
      page.getByRole("status").filter({ hasText: "built-in demo dataset, not from a live source" }),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Demo dataset" })).toBeVisible();
    await expect(page.getByText("This is not a live lookup.")).toBeVisible();

    // The network details and the verdict of the provider.
    await expect(page.getByText("AS64501")).toBeVisible();
    await expect(page.getByText("Harbor Demo Hosting (fictional)")).toBeVisible();
    await expect(page.getByText("gate.harbor-lights-c2.example")).toBeVisible();
    await expect(page.getByText("Malicious").first()).toBeVisible();
    await expect(
      page.getByRole("img", { name: /Analysis by 87 engines: 17 malicious/ }),
    ).toBeVisible();
    await expect(page.getByText("Engines that flagged it (4)")).toBeVisible();

    // What the workspace knows.
    await expect(page.getByText("Tracked in your workspace")).toBeVisible();
    await expect(page.getByRole("heading", { name: "In your workspace" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Related indicators" })).toBeVisible();
    await expect(page.getByText("resolves to this")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
    await expect(page.getByText("First seen", { exact: true })).toBeVisible();

    // What was asked.
    await expect(page.getByRole("heading", { name: "Sources" })).toBeVisible();
    await expect(page.getByText("Answered", { exact: true })).toBeVisible();

    await page.getByRole("link", { name: "Open indicator" }).click();
    await expect(page).toHaveURL(/\/indicators\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("indicator-value")).toHaveText("198.51.100.23");
  });

  test("a benign sample looks benign, and real subjects still say demo", async ({ page }) => {
    await page.goto("/intelligence/ip?q=8.8.8.8");
    await expect(page.getByTestId("intel-value")).toHaveText("8.8.8.8");
    await expect(page.getByText("Google LLC").first()).toBeVisible();
    await expect(page.getByText("United States")).toBeVisible();
    await expect(page.getByText("dns.google").first()).toBeVisible();
    await expect(page.getByText("Benign").first()).toBeVisible();
    await expect(page.getByText("Not tracked", { exact: true })).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Demo data" })).toBeVisible();
  });

  test("the box canonicalizes what is typed and the address records the lookup", async ({
    page,
  }) => {
    await page.goto("/intelligence/domain");
    await page
      .getByRole("textbox", { name: "Value to look up" })
      .fill("  HARBOR-Lights-C2.EXAMPLE ");
    await page.getByRole("button", { name: "Look up" }).click();
    await expect(page).toHaveURL(/\/intelligence\/domain\?q=HARBOR-Lights-C2\.EXAMPLE/i);
    await expect(page.getByTestId("intel-value")).toHaveText("harbor-lights-c2.example");
    await expect(page.getByText("Example Registrar Ltd (fictional)")).toBeVisible();
    await expect(page.getByRole("table", { name: "DNS records" })).toBeVisible();
    await expect(page.getByText("ns1.demo-dns.example").first()).toBeVisible();

    // Related IPs are lookups of their own.
    await page.locator('a[href="/intelligence/ip?q=198.51.100.23"]').first().click();
    await expect(page).toHaveURL(/\/intelligence\/ip\?q=198\.51\.100\.23$/);
    await expect(page.getByTestId("intel-value")).toHaveText("198.51.100.23");
  });

  test("a URL lookup shows the redirect chain and links to its domain", async ({ page }) => {
    const url = "http://invoice-download.example/files/invoice_2026.zip";
    await page.goto(`/intelligence/url?q=${encodeURIComponent(url)}`);
    await expect(page.getByTestId("intel-value")).toHaveText(url);
    await expect(page.getByRole("heading", { name: "Redirects" })).toBeVisible();
    await expect(
      page.getByText("https://invoice-download.example/dl/invoice_2026.zip").first(),
    ).toBeVisible();
    await page.locator('a[href="/intelligence/domain?q=invoice-download.example"]').first().click();
    await expect(page.getByTestId("intel-value")).toHaveText("invoice-download.example");
  });

  test("any digest of a sample finds it: file details, family and all three hashes", async ({
    page,
  }) => {
    await page.goto(`/intelligence/hash?q=${sample("md5")}`);
    await expect(page.getByTestId("intel-value")).toHaveText(sample("md5"));
    await expect(page.getByText("invoice_viewer.exe")).toBeVisible();
    // (Not just any text with the name: "Trojan.NightLoader" lives inside a closed details element.)
    await expect(page.getByText("NightLoader", { exact: true }).first()).toBeVisible();
    await expect(page.getByText(sample("sha256"))).toBeVisible();
    await expect(page.getByText("SHA-256", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("1.4 MB")).toBeVisible();

    await page.goto(`/intelligence/hash?q=${sample("sha256").toUpperCase()}`);
    await expect(page.getByTestId("intel-value")).toHaveText(sample("sha256"));
  });

  test("a subject the demo dataset lacks says so plainly and still shows the workspace's view", async ({
    page,
  }) => {
    await page.goto("/intelligence/ip?q=203.0.113.190");
    await expect(page.getByRole("heading", { name: "No intelligence found" })).toBeVisible();
    await expect(page.getByText("says nothing about whether the value is safe")).toBeVisible();
    await expect(page.getByText("Tracked in your workspace")).toBeVisible();
    await expect(page.getByText("Has no record of this value.", { exact: true })).toBeVisible();
  });

  test("a value of the wrong kind is refused, with a way to the right lookup", async ({ page }) => {
    await page.goto("/intelligence/ip?q=login.example");
    await expect(
      page.getByRole("alert").filter({ hasText: "can't be looked up here" }),
    ).toBeVisible();
    await expect(page.getByTestId("intel-result")).toHaveCount(0);
    await page.getByRole("link", { name: "Open Domain intelligence for it" }).click();
    await expect(page).toHaveURL(/\/intelligence\/domain\?q=login\.example/);
    await expect(
      page.getByRole("heading", { level: 1, name: "Domain intelligence" }),
    ).toBeVisible();
    await expect(page.getByTestId("intel-value")).toHaveText("login.example");
  });

  test("a private address is looked up locally only", async ({ page }) => {
    await page.goto("/intelligence/ip?q=10.0.0.1");
    await expect(page.getByTestId("intel-value")).toHaveText("10.0.0.1");
    await expect(page.getByRole("heading", { name: "No intelligence found" })).toBeVisible();
  });

  test("a viewer is told who can add an untracked subject, and gets no add button", async ({
    page,
  }) => {
    await page.goto("/intelligence/ip?q=203.0.113.77");
    await expect(page.getByText("is not tracked as an indicator in your workspace")).toBeVisible();
    await expect(page.getByText("Analysts and administrators can add it.")).toBeVisible();
    await expect(page.getByRole("link", { name: "Add as indicator" })).toHaveCount(0);
  });

  test("global search recognizes a value and offers its lookup first", async ({ page }) => {
    await page.goto("/dashboard");
    const box = page.getByRole("combobox", { name: "Search ArcRadar" });
    await box.fill("198.51.100.23");
    const offer = page.getByRole("option", { name: /Open IP intelligence for this IP address/ });
    await expect(offer).toBeVisible();
    await expect(page.getByRole("group", { name: "Look up" })).toBeVisible();
    await expect(page.getByRole("group", { name: "Indicators" })).toBeVisible();
    await box.press("ArrowDown");
    await expect(box).toHaveAttribute("aria-activedescendant", /option-0$/);
    await box.press("Enter");
    await expect(page).toHaveURL(/\/intelligence\/ip\?q=198\.51\.100\.23$/);
    await expect(page.getByTestId("intel-value")).toHaveText("198.51.100.23");
  });
});

test.describe("lookup pages (analyst)", () => {
  test.use({ storageState: STORAGE.analyst });

  test("an analyst can start tracking an untracked subject, pre-filled", async ({ page }) => {
    await page.goto("/intelligence/ip?q=203.0.113.77");
    await page.getByRole("link", { name: "Add as indicator" }).click();
    await expect(page).toHaveURL(/\/indicators\/new\?type=ipv4&value=203\.0\.113\.77$/);
    await expect(page.getByLabel("Type")).toHaveValue("ipv4");
    await expect(page.getByLabel("Value")).toHaveValue("203.0.113.77");
  });

  test("the pre-fill keeps the type the lookup found", async ({ page }) => {
    await page.goto(`/intelligence/hash?q=${"e".repeat(64)}`);
    await page.getByRole("link", { name: "Add as indicator" }).click();
    await expect(page.getByLabel("Type")).toHaveValue("sha256");
    await expect(page.getByLabel("Value")).toHaveValue("e".repeat(64));
  });

  test("with no live provider connected the analyst still gets labelled demo data", async ({
    page,
  }) => {
    await page.goto("/intelligence/domain?q=example.com");
    await expect(page.getByText("Reserved by IANA")).toBeVisible();
    await expect(page.getByText("RESERVED-Internet Assigned Numbers Authority")).toBeVisible();
    await expect(
      page.getByText("No live intelligence provider is connected to this workspace."),
    ).toBeVisible();
  });

  test("the pre-fill ignores odd parameters", async ({ page }) => {
    await page.goto("/indicators/new?type=nonsense&value=" + "x".repeat(3000));
    await expect(page.getByLabel("Type")).toHaveValue("ipv4");
    await expect(page.getByLabel("Value")).toHaveValue("");
  });
});

test.describe("vulnerabilities (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("the list has live statistics, provenance on every row and a live navigation entry", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    await nav.getByRole("link", { name: "Vulnerabilities" }).click();
    await expect(page).toHaveURL(/\/vulnerabilities$/);
    await expect(page).toHaveTitle("Vulnerabilities · ArcRadar");
    await expect(nav.getByRole("link", { name: "Vulnerabilities" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    await expect(stats(page).getByRole("link", { name: /All vulnerabilities/ })).toContainText(
      "12",
    );
    await expect(stats(page).getByRole("link", { name: /Exploited in the wild/ })).toContainText(
      "9",
    );
    await expect(rows(page)).toHaveCount(12);
    await expect(page.getByText("Demo data").filter({ visible: true })).toHaveCount(12);
  });

  test("a statistics tile filters the list, and is marked while it does", async ({ page }) => {
    await page.goto("/vulnerabilities");
    await stats(page)
      .getByRole("link", { name: /Critical/ })
      .click();
    await expect(page).toHaveURL(/severity=critical/);
    await expect(rows(page)).toHaveCount(6);
    for (const row of await rows(page).all()) {
      await expect(row.getByText("Critical").filter({ visible: true }).first()).toBeVisible();
    }
    await expect(stats(page).getByRole("link", { name: /Critical/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
    await expect(page.getByText("6 vulnerabilities match")).toBeVisible();
  });

  test("search, filters and sorting work and live in the address", async ({ page }) => {
    await page.goto("/vulnerabilities");

    await page.getByRole("searchbox", { name: "Search vulnerabilities" }).fill("log4j");
    await expect(page).toHaveURL(/q=log4j/);
    await expect(rows(page)).toHaveCount(1);
    await expect(page.getByText("1 vulnerability matches")).toBeVisible();

    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await expect(page).not.toHaveURL(/q=/);
    await expect(rows(page)).toHaveCount(12);

    await page.getByRole("searchbox", { name: "Search vulnerabilities" }).fill("microsoft");
    await expect(page).toHaveURL(/q=microsoft/);
    await expect(rows(page)).toHaveCount(6);
    await page.getByRole("button", { name: "Clear search and filters" }).click();

    await page
      .getByRole("combobox", { name: "Exploit status", exact: true })
      .selectOption("poc_available");
    await expect(page).toHaveURL(/exploit_status=poc_available/);
    await expect(rows(page)).toHaveCount(3);
    await page.getByRole("button", { name: "Clear search and filters" }).click();

    await page.getByRole("combobox", { name: "CVSS score", exact: true }).selectOption("9");
    await expect(page).toHaveURL(/min_cvss=9/);
    await expect(rows(page)).toHaveCount(6);
  });

  test("column headers sort, a second click reverses, and severity sorts by rank", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities");
    const header = page.getByRole("columnheader", { name: /^CVSS/ });

    await header.getByRole("link").click();
    await expect(page).toHaveURL(/sort=cvss_score&order=asc/);
    await expect(header).toHaveAttribute("aria-sort", "ascending");
    await expect(rows(page).first()).toContainText("CVSS 7.5");

    await header.getByRole("link").click();
    await expect(page).toHaveURL(/sort=cvss_score&order=desc/);
    await expect(header).toHaveAttribute("aria-sort", "descending");
    await expect(rows(page).first()).toContainText("CVSS 10.0");

    const severity = page.getByRole("columnheader", { name: /^Severity/ }).getByRole("link");
    await severity.click();
    await expect(page).toHaveURL(/sort=severity&order=asc/);
    await expect(rows(page).first()).toContainText("High");
    await severity.click();
    await expect(page).toHaveURL(/sort=severity&order=desc/);
    await expect(rows(page).first()).toContainText("Critical");
  });

  test("a hand-edited or stale address never breaks the list", async ({ page }) => {
    await page.goto("/vulnerabilities?severity=nope");
    await expect(page.getByText("Some options in the address were not valid")).toBeVisible();
    await expect(rows(page)).toHaveCount(12);

    await page.goto("/vulnerabilities?page=9");
    await expect(page.getByRole("heading", { name: "That page is past the end" })).toBeVisible();
    await page.getByRole("link", { name: "Go to the last page" }).click();
    await expect(rows(page).first()).toBeVisible();

    await page.goto("/vulnerabilities?q=zzz-nothing");
    await expect(page.getByRole("heading", { name: "No vulnerabilities match" })).toBeVisible();
    await expect(page.getByText("Try fewer words")).toBeVisible();
  });

  test("a CVE that is not in the database offers no import when no provider is connected", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities?q=CVE-2099-0001");
    await expect(page.getByRole("heading", { name: "No vulnerabilities match" })).toBeVisible();
    await expect(page.getByText("CVE-2099-0001 is not in your database.")).toBeVisible();
    await expect(page.getByRole("button", { name: /Import/ })).toHaveCount(0);
  });

  test("a CVE page has its score, affected products, remediation and safe reference links", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities/CVE-2021-44228");
    await expect(page).toHaveTitle("CVE-2021-44228 · Vulnerabilities · ArcRadar");
    await expect(page.getByTestId("vulnerability-id")).toHaveText("CVE-2021-44228");
    await expect(page.getByRole("status").filter({ hasText: "This is demo data" })).toBeVisible();

    await expect(page.getByRole("table", { name: "Affected products" })).toContainText("Apache");
    await expect(page.getByRole("table", { name: "Affected products" })).toContainText("2.15.0");
    await expect(page.getByText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBeVisible();
    await expect(page.getByText("Exploited in the wild").first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Remediation" })).toBeVisible();
    await expect(page.getByText("10 Dec 2021")).toBeVisible();

    const reference = page.getByRole("link", { name: /nvd\.nist\.gov/ });
    await expect(reference).toHaveAttribute("target", "_blank");
    await expect(reference).toHaveAttribute("rel", /noopener/);

    // No provider is connected and a viewer cannot refresh anyway.
    await expect(page.getByRole("button", { name: /Refresh from/ })).toHaveCount(0);

    await page.getByRole("link", { name: "Open indicator" }).click();
    await expect(page).toHaveURL(/\/indicators\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("indicator-value")).toHaveText("CVE-2021-44228");
  });

  test("the id in the address may be lower case; unknown and malformed ids are not found", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities/cve-2021-44228");
    await expect(page.getByTestId("vulnerability-id")).toHaveText("CVE-2021-44228");
    for (const id of ["CVE-2099-0001", "not-a-cve"]) {
      await page.goto(`/vulnerabilities/${id}`);
      await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
      await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    }
  });

  test("global search finds a CVE and opens it with the keyboard", async ({ page }) => {
    await page.goto("/dashboard");
    const box = page.getByRole("combobox", { name: "Search ArcRadar" });
    await box.fill("log4j");
    await expect(page.getByRole("group", { name: "Vulnerabilities" })).toBeVisible();
    const option = page.getByRole("option", { name: /CVE-2021-44228/ });
    await expect(option).toContainText("Critical · CVSS 10.0");
    await expect(option).toContainText("Demo data");
    await box.press("ArrowDown");
    await box.press("Enter");
    await expect(page).toHaveURL(/\/vulnerabilities\/CVE-2021-44228$/);
  });
});

test.describe("vulnerabilities (admin)", () => {
  test.use({ storageState: STORAGE.admin });

  test("without a connected provider there is nothing to import or refresh, even for an administrator", async ({
    page,
  }) => {
    await page.goto("/vulnerabilities/CVE-2021-44228");
    await expect(page.getByTestId("vulnerability-id")).toBeVisible();
    // Demo records are never refreshed from a provider, and none is connected in any case.
    await expect(page.getByRole("button", { name: /Refresh from/ })).toHaveCount(0);

    await page.goto("/vulnerabilities?q=CVE-2099-0001");
    await expect(page.getByText("CVE-2099-0001 is not in your database.")).toBeVisible();
    await expect(page.getByRole("button", { name: /Import/ })).toHaveCount(0);
  });
});
