import { expect, test, type Page } from "@playwright/test";
import { adminFetch, STORAGE } from "./support";

const rows = (page: Page) => page.locator("tbody tr");
const searchBox = (page: Page) => page.getByRole("searchbox", { name: "Search indicators" });

/** Removes an indicator (and stray e2e tags) with the service role, whatever state a test ended in. */
async function cleanUp(value: string) {
  await adminFetch(`/rest/v1/indicators?value=eq.${encodeURIComponent(value)}`, {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/tags?name=ilike.e2e-*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
}

test.describe("browsing indicators (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("lists indicators with provenance on every row and a live navigation entry", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    await nav.getByRole("link", { name: "Indicators" }).click();
    await expect(page).toHaveURL(/\/indicators$/);
    await expect(page).toHaveTitle("Indicators · ArcRadar");
    await expect(nav.getByRole("link", { name: "Indicators" })).toHaveAttribute(
      "aria-current",
      "page",
    );

    await expect(page.getByText(/^\d+ indicators$/)).toBeVisible();
    await expect(rows(page)).toHaveCount(25);
    // Every seeded record is demo data, and says so.
    // (Below wide layouts the badges sit under the value instead of in a column, so count visible ones.)
    await expect(page.getByText("Demo data").filter({ visible: true })).toHaveCount(25);
  });

  test("a viewer can read but not create, edit or delete", async ({ page }) => {
    await page.goto("/indicators");
    await expect(page.getByRole("link", { name: "New indicator" })).toHaveCount(0);

    await page.goto("/indicators/new");
    await expect(page.getByRole("heading", { name: "You can't add indicators" })).toBeVisible();

    await page.goto("/indicators?q=harbor");
    await page.getByRole("cell").getByRole("link").first().click();
    await expect(page.getByTestId("indicator-value")).toBeVisible();
    await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
  });

  test("searching updates the address, narrows the list and can be cleared", async ({ page }) => {
    await page.goto("/indicators");
    await searchBox(page).fill("phishing");
    await expect(page).toHaveURL(/[?&]q=phishing/);
    await expect(page.getByText(/indicators match$/)).toBeVisible();
    const count = await rows(page).count();
    expect(count).toBeGreaterThan(0);
    expect(count).toBeLessThan(25);

    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await expect(page).toHaveURL(/\/indicators$/);
    await expect(searchBox(page)).toHaveValue("");
    await expect(rows(page)).toHaveCount(25);
  });

  test("filters combine, appear in the address and survive a reload", async ({ page }) => {
    await page.goto("/indicators");
    await page.getByRole("combobox", { name: "Type", exact: true }).selectOption("domain");
    await page.getByRole("combobox", { name: "Verdict", exact: true }).selectOption("malicious");
    await expect(page).toHaveURL(/type=domain/);
    await expect(page).toHaveURL(/verdict=malicious/);

    const total = await page.getByText(/indicators match$/).textContent();
    await page.reload();
    await expect(page.getByRole("combobox", { name: "Type", exact: true })).toHaveValue("domain");
    await expect(page.getByRole("combobox", { name: "Verdict", exact: true })).toHaveValue(
      "malicious",
    );
    await expect(page.getByText(/indicators match$/)).toHaveText(total ?? "");
    // Every visible row is a malicious domain: the verdict badge is on each one, none say Benign.
    const visible = (text: string) =>
      page.locator("tbody tr").getByText(text, { exact: true }).filter({ visible: true });
    await expect(visible("Malicious")).toHaveCount(await page.locator("tbody tr").count());
    await expect(visible("Benign")).toHaveCount(0);
    await expect(visible("Domain")).toHaveCount(await page.locator("tbody tr").count());
  });

  test("a tag filter shows only records with that tag", async ({ page }) => {
    await page.goto("/indicators");
    await page.getByRole("combobox", { name: "Tag", exact: true }).selectOption("ransomware");
    await expect(page).toHaveURL(/tag=ransomware/);
    const list = page.locator("tbody tr");
    await expect(list.first()).toBeVisible();
    for (const row of await list.all()) await expect(row).toContainText("ransomware");
  });

  test("no matches shows a helpful empty state", async ({ page }) => {
    await page.goto("/indicators?q=zzz-nothing-matches");
    await expect(page.getByRole("heading", { name: "No indicators match" })).toBeVisible();
    await page.getByRole("link", { name: "Clear search and filters" }).click();
    await expect(page).toHaveURL(/\/indicators$/);
    await expect(rows(page)).toHaveCount(25);
  });

  test("column headers sort, mark the sorted column, and reverse on a second click", async ({
    page,
  }) => {
    await page.goto("/indicators");
    const confidence = page.getByRole("columnheader", { name: /Confidence/ });
    await confidence.getByRole("link").click();
    await expect(page).toHaveURL(/sort=confidence&order=asc/);
    await expect(confidence).toHaveAttribute("aria-sort", "ascending");
    const values = async () =>
      (await page.locator("tbody tr").locator("td:nth-child(5)").allTextContents()).map((text) =>
        Number.parseInt(text, 10),
      );
    const ascending = await values();
    expect(ascending).toEqual([...ascending].sort((a, b) => a - b));

    await page
      .getByRole("columnheader", { name: /Confidence/ })
      .getByRole("link")
      .click();
    await expect(page).toHaveURL(/sort=confidence&order=desc/);
    const descending = await values();
    expect(descending).toEqual([...descending].sort((a, b) => b - a));
  });

  test("severity sorts by rank, not alphabetically", async ({ page }) => {
    await page.goto("/indicators?sort=severity&order=desc");
    await expect(rows(page).first()).toContainText("Critical");
    await page.goto("/indicators?sort=severity&order=asc");
    await expect(rows(page).first()).toContainText("Info");
  });

  test("pages through the results and reports where you are", async ({ page }) => {
    await page.goto("/indicators");
    await expect(page.getByText(/^Showing 1–25 of \d+ indicators$/)).toBeVisible();
    await page.getByRole("link", { name: "Next page" }).click();
    await expect(page).toHaveURL(/page=2/);
    await expect(page.getByText(/^Showing 26–\d+ of \d+ indicators$/)).toBeVisible();
    await expect(page.getByRole("link", { name: "Page 2" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(page.getByRole("link", { name: "Next page" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  test("a hand-edited address never breaks the page", async ({ page }) => {
    await page.goto("/indicators?page_size=1000&sort=password&type=nope");
    await expect(page.getByText(/were not valid, so the default view is shown/)).toBeVisible();
    await expect(rows(page)).toHaveCount(25);

    await page.goto("/indicators?page=99");
    await expect(page.getByRole("heading", { name: "That page is past the end" })).toBeVisible();
    await page.getByRole("link", { name: "Go to the last page" }).click();
    await expect(rows(page).first()).toBeVisible();
  });

  test("the detail page shows the assessment, provenance, links and relationships", async ({
    page,
  }) => {
    await page.goto("/indicators?q=198.51.100.23");
    await page.getByRole("cell").getByRole("link", { name: "198.51.100.23", exact: true }).click();
    await expect(page.getByTestId("indicator-value")).toHaveText("198.51.100.23");
    await expect(page).toHaveTitle("198.51.100.23 · Indicators · ArcRadar");
    await expect(
      page.getByRole("alert").or(page.getByRole("status")).filter({ hasText: "demo data" }),
    ).toBeVisible();

    const main = page.getByRole("main");
    await expect(main.getByRole("heading", { name: "Relationships" })).toBeVisible();
    await expect(main.getByRole("link", { name: /harbor-lights-c2\.example/ })).toBeVisible();
    await expect(main.getByText("Crimson Harbor")).toBeVisible();
    await expect(main.getByText("Confidence")).toBeVisible();

    // A related indicator is a link to its own page.
    await main
      .getByRole("link", { name: /harbor-lights-c2\.example/ })
      .first()
      .click();
    await expect(page.getByTestId("indicator-value")).toHaveText("harbor-lights-c2.example");
  });

  test("a missing or malformed id shows not-found inside the app shell", async ({ page }) => {
    for (const id of ["00000000-0000-4000-8000-000000000000", "not-a-uuid"]) {
      await page.goto(`/indicators/${id}`);
      await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
      await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    }
  });
});

test.describe("global search", () => {
  test.use({ storageState: STORAGE.viewer });

  test("the / key focuses it, results show provenance, and arrows plus Enter open one", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    await page.keyboard.press("/");
    const box = page.getByRole("combobox", { name: "Search ArcRadar" });
    await expect(box).toBeFocused();

    await box.fill("harbor");
    const domain = page
      .getByRole("option")
      .filter({ has: page.getByText("harbor-lights-c2.example", { exact: true }) });
    await expect(domain).toContainText("Demo data");
    await expect(page.getByRole("option", { name: /Search indicators for/ })).toBeVisible();
    await expect(box).toHaveAttribute("aria-expanded", "true");

    // Several demo indicators match "harbor" and share a last_seen, so their order is not fixed:
    // walk down to the domain instead of assuming it comes first.
    const domainId = (await domain.getAttribute("id")) ?? "";
    expect(domainId).toMatch(/-option-\d+$/);
    for (let step = 0; step <= Number(domainId.split("-option-")[1]); step++) {
      await box.press("ArrowDown");
    }
    await expect(box).toHaveAttribute("aria-activedescendant", domainId);
    await box.press("Enter");
    await expect(page).toHaveURL(/\/indicators\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("indicator-value")).toHaveText("harbor-lights-c2.example");
  });

  test("waits for two characters, Enter searches the list, Escape closes then clears", async ({
    page,
  }) => {
    await page.goto("/dashboard");
    const box = page.getByRole("combobox", { name: "Search ArcRadar" });
    await box.fill("h");
    await expect(page.getByRole("listbox")).toHaveCount(0);

    await box.fill("phish");
    await expect(page.getByRole("listbox")).toBeVisible();
    await box.press("Escape");
    await expect(page.getByRole("listbox")).toHaveCount(0);
    await expect(box).toHaveValue("phish");
    await box.press("Escape");
    await expect(box).toHaveValue("");

    await box.fill("phish");
    await expect(page.getByRole("listbox")).toBeVisible();
    await box.press("Enter");
    await expect(page).toHaveURL(/\/indicators\?q=phish$/);
    await expect(rows(page).first()).toBeVisible();
  });

  test("says so when nothing matches", async ({ page }) => {
    await page.goto("/dashboard");
    await page.getByRole("combobox", { name: "Search ArcRadar" }).fill("zzz-nothing-matches");
    await expect(page.getByText("No matches for “zzz-nothing-matches”.")).toBeVisible();
  });

  test("Ctrl+K also focuses the search from inside the page", async ({ page }) => {
    await page.goto("/indicators");
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("combobox", { name: "Search ArcRadar" })).toBeFocused();
  });
});

test.describe("creating, editing and deleting (analyst and admin)", () => {
  test.use({ storageState: STORAGE.analyst });

  test("form validates in the browser before any request is sent", async ({ page }) => {
    const calls: string[] = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && request.url().includes("/api/indicators")) {
        calls.push(request.url());
      }
    });

    await page.goto("/indicators/new");
    await page.getByLabel("Value").fill("999.1.1.1");
    await page.getByLabel("Value").blur();
    await expect(page.getByText("Enter a valid IPv4 address, such as 203.0.113.10.")).toBeVisible();

    // The hint follows the chosen type.
    await page.getByLabel("Type").selectOption("sha256");
    await expect(page.getByText("Enter a valid IPv4 address")).toHaveCount(0);
    await expect(page.getByLabel("Value")).toHaveAttribute(
      "placeholder",
      "64 hexadecimal characters",
    );

    await page.getByRole("button", { name: "Create indicator" }).click();
    await expect(page.getByText("A SHA-256 hash has 64 hexadecimal characters.")).toBeVisible();
    await page.getByLabel("Confidence (0–100)").fill("150");
    await page.getByRole("button", { name: "Create indicator" }).click();
    await expect(page.getByText("Confidence cannot be above 100.")).toBeVisible();
    expect(calls).toHaveLength(0);
  });

  test("tags are added with Enter, removed with their button, and validated", async ({ page }) => {
    await page.goto("/indicators/new");
    const tags = page.getByLabel("Tags");
    await tags.fill("c2");
    await tags.press("Enter");
    await tags.fill("Phishing");
    await tags.press(",");
    await tags.fill("C2"); // a duplicate, ignoring case
    await tags.press("Enter");
    await expect(page.getByRole("button", { name: /Remove tag/ })).toHaveCount(2);
    await expect(page.getByText("2 of 20 used.")).toBeVisible();

    await tags.fill("<script>");
    await tags.press("Enter");
    await expect(page.getByText(/Tags may contain letters, numbers/)).toBeVisible();

    await page.getByRole("button", { name: "Remove tag c2" }).click();
    await expect(page.getByRole("button", { name: /Remove tag/ })).toHaveCount(1);
  });

  test("create, see it as local data, edit it, and reject a duplicate", async ({ page }) => {
    const value = `e2e-${Date.now()}.example`;
    try {
      await page.goto("/indicators/new");
      await page.getByLabel("Type").selectOption("domain");
      await page.getByLabel("Value").fill(value.toUpperCase());
      await page.getByLabel("Verdict").selectOption("suspicious");
      await page.getByLabel("Severity").selectOption("high");
      await page.getByLabel("Confidence (0–100)").fill("77");
      await page.getByLabel("Description").fill("Created by an end-to-end test.");
      await page.getByLabel("Tags").fill("e2e-tag");
      await page.getByLabel("Tags").press("Enter");
      await page.getByRole("button", { name: "Create indicator" }).click();

      // Lands on the new record: stored in lower case, labelled as local data.
      await expect(page).toHaveURL(/\/indicators\/[0-9a-f-]{36}$/);
      await expect(page.getByTestId("indicator-value")).toHaveText(value);
      await expect(
        page.getByRole("main").getByText("Local", { exact: true }).first(),
      ).toBeVisible();
      await expect(page.getByRole("status").filter({ hasText: "Local data" })).toBeVisible();
      await expect(page.getByRole("main").getByText("e2e-tag")).toBeVisible();
      await expect(page.getByRole("main").getByText("Demo Analyst")).toBeVisible(); // Added by
      // An analyst cannot delete.
      await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
      const detailUrl = page.url();

      // Editing: type and value are fixed, the rest can change, tags are replaced.
      await page.getByRole("link", { name: "Edit" }).click();
      await expect(page.getByRole("form", { name: "Edit indicator" })).toBeVisible();
      await expect(page.getByLabel("Value")).toHaveCount(0);
      await expect(page.getByText("cannot be changed")).toBeVisible();
      await page.getByLabel("Severity").selectOption("critical");
      await page.getByLabel("Description").fill("");
      await page.getByRole("button", { name: "Remove tag e2e-tag" }).click();
      await page.getByLabel("Tags").fill("e2e-other");
      await page.getByLabel("Tags").press("Enter");
      await page.getByRole("button", { name: "Save changes" }).click();
      await expect(page).toHaveURL(detailUrl);
      await expect(page.getByRole("main").getByText("No description.")).toBeVisible();
      await expect(page.getByRole("main").getByText("e2e-other")).toBeVisible();
      await expect(page.getByRole("main").getByText("e2e-tag")).toHaveCount(0);
      await expect(page.getByTestId("indicator-value")).toBeVisible();
      await expect(page.locator("dl").getByText("Critical")).toBeVisible();

      // A duplicate (any letter case) is refused and points at the existing record.
      await page.goto("/indicators/new");
      await page.getByLabel("Type").selectOption("domain");
      await page.getByLabel("Value").fill(value);
      await page.getByRole("button", { name: "Create indicator" }).click();
      await expect(page.getByRole("alert").filter({ hasText: "already exists" })).toBeVisible();
      await page.getByRole("link", { name: "View the existing indicator" }).click();
      await expect(page).toHaveURL(detailUrl);
    } finally {
      await cleanUp(value);
    }
  });
});

test.describe("deleting (admin)", () => {
  test.use({ storageState: STORAGE.admin });

  test("delete asks for confirmation, can be cancelled, and removes the record", async ({
    page,
  }) => {
    const value = `e2e-del-${Date.now()}.example`;
    try {
      await page.goto("/indicators/new");
      await page.getByLabel("Type").selectOption("domain");
      await page.getByLabel("Value").fill(value);
      await page.getByRole("button", { name: "Create indicator" }).click();
      await expect(page.getByTestId("indicator-value")).toHaveText(value);
      const detailUrl = page.url();

      await page.getByRole("button", { name: "Delete" }).click();
      const dialog = page.getByRole("dialog", { name: "Delete this indicator?" });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      await expect(page).toHaveURL(detailUrl);

      await page.getByRole("button", { name: "Delete" }).click();
      await dialog.getByRole("button", { name: "Delete indicator" }).click();
      await expect(page).toHaveURL(/\/indicators$/);

      await page.goto(detailUrl);
      await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
    } finally {
      await cleanUp(value);
    }
  });
});
