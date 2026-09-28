import { expect, test, type Page } from "@playwright/test";
import { adminFetch, STORAGE } from "./support";

const rows = (page: Page) => page.locator("tbody tr");
const stamp = Date.now();

/** Removes what the tests created (by name prefix) with the service role, whatever state they ended in. */
async function cleanUp() {
  for (const [table, column, pattern] of [
    ["threat_actors", "name", "E2E*"],
    ["campaigns", "name", "E2E*"],
    ["malware", "name", "E2E*"],
    ["indicators", "value", "e2e-*"],
  ]) {
    await adminFetch(`/rest/v1/${table}?${column}=like.${pattern}`, {
      method: "DELETE",
      headers: { prefer: "return=minimal" },
    });
  }
}

test.afterAll(cleanUp);

test.describe("threat intelligence (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("the four pages are live in the navigation", async ({ page }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    for (const [label, path, heading] of [
      ["Threat actors", "/threat-actors", "Threat actors"],
      ["Campaigns", "/campaigns", "Campaigns"],
      ["Malware", "/malware", "Malware"],
      ["MITRE ATT&CK", "/mitre", "MITRE ATT&CK"],
    ] as const) {
      await nav.getByRole("link", { name: label }).click();
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page).toHaveTitle(`${heading} · ArcRadar`);
      await expect(nav.getByRole("link", { name: label })).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    }
  });

  test("the actor list is sorted by name, labelled demo, and searchable", async ({ page }) => {
    await page.goto("/threat-actors");
    await expect(page.getByText("5 threat actors", { exact: true })).toBeVisible();
    await expect(rows(page)).toHaveCount(5);
    await expect(rows(page).first()).toContainText("Ashen Tide");
    await expect(page.getByText("Demo data").filter({ visible: true })).toHaveCount(5);

    const search = page.getByRole("searchbox", { name: "Search threat actors" });
    await search.fill("crimson");
    await expect(page).toHaveURL(/[?&]q=crimson/);
    await expect(rows(page)).toHaveCount(1);
    await expect(page.getByText("1 threat actor matches", { exact: true })).toBeVisible();

    // Aliases and target industries are searched too, and every word has to match.
    await search.fill("DEMO-FIN");
    await expect(rows(page)).toHaveCount(2);
    await search.fill("retail hospitality");
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("Iron Orchard");

    await search.fill("zzz-nothing-matches");
    await expect(page.getByRole("heading", { name: "No threat actors match" })).toBeVisible();
    await page.getByRole("link", { name: "Clear search and filters" }).click();
    await expect(page).toHaveURL(/\/threat-actors$/);
  });

  test("column headers sort the actors, and the address remembers it", async ({ page }) => {
    await page.goto("/threat-actors");
    await page
      .getByRole("columnheader", { name: /Threat actor/ })
      .getByRole("link")
      .click();
    await expect(page).toHaveURL(/sort=name&order=desc/);
    await expect(rows(page).first()).toContainText("Velvet Signal");

    await page
      .getByRole("columnheader", { name: /Last seen/ })
      .getByRole("link")
      .click();
    await expect(page).toHaveURL(/sort=last_seen&order=asc/);
    await page.reload();
    await expect(page.getByRole("columnheader", { name: /Last seen/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
  });

  test("an actor's page shows what it uses, with provenance, and links onward", async ({
    page,
  }) => {
    await page.goto("/threat-actors?q=crimson");
    await rows(page).first().getByRole("link", { name: "Crimson Harbor" }).click();
    await expect(page).toHaveURL(/\/threat-actors\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText("Crimson Harbor");
    await expect(page.getByText("This is demo data")).toBeVisible();
    await expect(page.getByText("Also known as DEMO-FIN-01")).toBeVisible();
    await expect(page.getByText("Financial gain")).toBeVisible();
    // Attribution is only shown when documented; the demo actors have none.
    await expect(page.getByText("Not attributed")).toBeVisible();

    await expect(page.getByRole("link", { name: "InkSteal" })).toBeVisible();
    await expect(page.getByRole("link", { name: "T1566" })).toBeVisible();
    // Every linked record carries its own provenance label.
    for (const linked of ["NightLoader", "InkSteal", "Harbor Lights"]) {
      await expect(
        page.getByRole("listitem").filter({ has: page.getByRole("link", { name: linked }) }),
      ).toContainText("Demo data");
    }
    await expect(page.getByRole("heading", { name: "Indicators" })).toBeVisible();

    // Nothing to change for a viewer.
    await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);

    await page.getByRole("link", { name: "NightLoader" }).click();
    await expect(page).toHaveURL(/\/malware\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText("NightLoader");
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Ashen Tide" })).toBeVisible();
  });

  test("campaigns filter by status and open with their actors", async ({ page }) => {
    await page.goto("/campaigns");
    await expect(rows(page)).toHaveCount(4);
    // Newest activity first.
    await expect(rows(page).first()).toContainText("Harbor Lights");

    await page.getByRole("combobox", { name: "Status", exact: true }).selectOption("active");
    await expect(page).toHaveURL(/status=active/);
    await expect(rows(page)).toHaveCount(2);

    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await page.getByRole("searchbox", { name: "Search campaigns" }).fill("ransomware");
    await expect(rows(page)).toHaveCount(1);
    await rows(page).first().getByRole("link", { name: "Winter Ledger" }).click();
    await expect(page.getByTestId("record-title")).toHaveText("Winter Ledger");
    await expect(page.getByText("Concluded").first()).toBeVisible();
    await expect(page.getByText("This is demo data")).toBeVisible();
    await expect(page.getByRole("link", { name: "Ashen Tide" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
  });

  test("malware filters by type, searches platforms and opens with its actors", async ({
    page,
  }) => {
    await page.goto("/malware");
    await expect(rows(page)).toHaveCount(6);

    await page.getByRole("combobox", { name: "Type", exact: true }).selectOption("Ransomware");
    await expect(page).toHaveURL(/type=Ransomware/);
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("EmberLock");

    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await page.getByRole("searchbox", { name: "Search malware" }).fill("macos");
    await expect(rows(page)).toHaveCount(1);
    await rows(page).first().getByRole("link", { name: "InkSteal" }).click();
    await expect(page.getByTestId("record-title")).toHaveText("InkSteal");
    await expect(page.getByText("macOS")).toBeVisible();
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Iron Orchard" })).toBeVisible();
  });

  test("ATT&CK techniques filter by tactic and say who uses them", async ({ page }) => {
    await page.goto("/mitre");
    await expect(page.getByText("15 techniques", { exact: true })).toBeVisible();
    await expect(page.getByText(/not a live feed/)).toBeVisible();

    await page
      .getByRole("combobox", { name: "Tactic", exact: true })
      .selectOption("Initial Access");
    await expect(page).toHaveURL(/tactic=Initial\+Access/);
    await expect(rows(page)).toHaveCount(3);

    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await page.getByRole("searchbox", { name: "Search techniques" }).fill("phishing");
    await expect(rows(page)).toHaveCount(1);
    await rows(page).first().getByRole("link", { name: "T1566" }).click();

    await expect(page).toHaveURL(/\/mitre\/T1566$/);
    await expect(page.getByTestId("record-title")).toContainText("T1566 Phishing");
    await expect(page.getByText("MITRE ATT&CK reference data")).toBeVisible();
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Iron Orchard" })).toBeVisible();
    const reference = page.getByRole("link", { name: /attack\.mitre\.org/ });
    await expect(reference).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1566/");
    await expect(reference).toHaveAttribute("target", "_blank");
    await expect(reference).toHaveAttribute("rel", /noopener/);
  });

  test("the address accepts a technique id in lower case; unknown and malformed ids are not found", async ({
    page,
  }) => {
    await page.goto("/mitre/t1566");
    await expect(page.getByTestId("record-title")).toContainText("T1566");
    for (const path of [
      "/mitre/T9999",
      "/mitre/nope",
      "/threat-actors/not-a-uuid",
      "/campaigns/x",
    ]) {
      await page.goto(path);
      await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
    }
  });

  test("viewers cannot add or edit threat intelligence", async ({ page }) => {
    for (const [list, add, heading] of [
      ["/threat-actors", "New threat actor", "You can't add threat actors"],
      ["/campaigns", "New campaign", "You can't add campaigns"],
      ["/malware", "New malware family", "You can't add malware families"],
    ] as const) {
      await page.goto(list);
      await expect(page.getByRole("link", { name: add })).toHaveCount(0);
      await page.goto(`${list}/new`);
      await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    }
  });

  test("global search finds threat intelligence, alerts and investigations", async ({ page }) => {
    await page.goto("/dashboard");
    const search = page.getByRole("combobox", { name: "Search ArcRadar" });
    await search.fill("harbor");
    const listbox = page.getByRole("listbox", { name: "Search results" });
    for (const group of ["Threat actors", "Campaigns", "Alerts", "Investigations"]) {
      await expect(listbox.getByRole("group", { name: group })).toBeVisible();
    }
    // Each hit says where it came from.
    await expect(
      listbox.getByRole("group", { name: "Threat actors" }).getByText("Demo data"),
    ).toBeVisible();

    await listbox.getByRole("option", { name: /Crimson Harbor/ }).click();
    await expect(page).toHaveURL(/\/threat-actors\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText("Crimson Harbor");

    await page.getByRole("combobox", { name: "Search ArcRadar" }).fill("T1566");
    await page.getByRole("option", { name: /T1566 Phishing/ }).click();
    await expect(page).toHaveURL(/\/mitre\/T1566$/);
  });
});

test.describe("linking indicators (analyst)", () => {
  test.use({ storageState: STORAGE.analyst });
  test.setTimeout(90_000);

  test("threat actors, campaigns and malware are linked and unlinked from the indicator", async ({
    page,
  }) => {
    const created = await page.request.post("/api/indicators", {
      data: { type: "domain", value: `e2e-links-${stamp}.example` },
    });
    expect(created.status()).toBe(201);
    const id = (await created.json()).data.id as string;

    // An analyst reads threat intelligence but does not curate it.
    await page.goto("/threat-actors");
    await expect(page.getByRole("link", { name: "New threat actor" })).toHaveCount(0);
    await page.goto("/threat-actors/new");
    await expect(page.getByRole("heading", { name: "You can't add threat actors" })).toBeVisible();

    await page.goto(`/indicators/${id}`);
    await expect(page.getByText("None linked.")).toHaveCount(3);
    await page.getByRole("button", { name: "Edit links" }).click();
    const form = page.getByRole("form", { name: "Edit linked intelligence" });
    await expect(form).toBeVisible();
    await form.getByRole("checkbox", { name: "Crimson Harbor" }).check();
    await form.getByRole("checkbox", { name: "Harbor Lights" }).check();
    await form.getByRole("checkbox", { name: /^NightLoader/ }).check();
    await expect(form.getByRole("group", { name: "Threat actors (1 selected)" })).toBeVisible();
    await form.getByRole("button", { name: "Save links" }).click();

    await expect(form).toBeHidden();
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toHaveAttribute(
      "href",
      /\/threat-actors\/[0-9a-f-]{36}$/,
    );
    await expect(page.getByRole("link", { name: "Harbor Lights" })).toBeVisible();
    await expect(page.getByRole("link", { name: "NightLoader" })).toBeVisible();
    await expect(page.getByText("None linked.")).toHaveCount(0);

    // The actor shows the indicator from its side.
    await page.getByRole("link", { name: "Crimson Harbor" }).click();
    await expect(page.getByRole("link", { name: `e2e-links-${stamp}.example` })).toBeVisible();
    await page.goBack();

    // Unlink one kind; the others stay.
    await page.getByRole("button", { name: "Edit links" }).click();
    await form.getByRole("checkbox", { name: "Crimson Harbor" }).uncheck();
    await form.getByRole("button", { name: "Save links" }).click();
    await expect(form).toBeHidden();
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "NightLoader" })).toBeVisible();
    await expect(page.getByText("None linked.")).toHaveCount(1);
  });

  test("two indicators can be related, and the relationship removed", async ({ page }) => {
    const first = `e2e-rel-a-${stamp}.example`;
    const second = `e2e-rel-b-${stamp}.example`;
    let ids: string[] = [];
    for (const value of [first, second]) {
      const response = await page.request.post("/api/indicators", {
        data: { type: "domain", value },
      });
      expect(response.status()).toBe(201);
      ids = [...ids, (await response.json()).data.id as string];
    }

    await page.goto(`/indicators/${ids[0]}`);
    await expect(page.getByText("No related indicators.")).toBeVisible();
    await page.getByLabel(/This indicator/).selectOption("resolves_to");
    await page.getByLabel(/this other indicator/i).fill(`e2e-rel-b-${stamp}`);
    await page.getByRole("button", { name: new RegExp(second.replace(/\./g, "\\.")) }).click();

    const relationship = page.getByRole("listitem").filter({ hasText: second });
    await expect(relationship).toContainText("resolves to");
    await expect(page.getByText("No related indicators.")).toHaveCount(0);

    // From the other side it reads the other way round.
    await relationship.getByRole("link", { name: second }).click();
    await expect(page.getByTestId("indicator-value")).toHaveText(second);
    await expect(page.getByText("resolves to this indicator")).toBeVisible();
    await page.goBack();

    await page.getByRole("button", { name: `Remove the relationship with ${second}` }).click();
    await expect(page.getByText("No related indicators.")).toBeVisible();
  });
});

test.describe("curating threat intelligence (administrator)", () => {
  test.use({ storageState: STORAGE.admin });
  test.setTimeout(120_000);

  test("add, edit and delete a threat actor, with its links", async ({ page }) => {
    const name = `E2E Actor ${stamp}`;
    await page.goto("/threat-actors");
    await page.getByRole("link", { name: "New threat actor" }).click();
    const form = page.getByRole("form", { name: "New threat actor" });
    await expect(form).toBeVisible();

    // Checked in the browser first.
    await form.getByRole("button", { name: "Create threat actor" }).click();
    await expect(form.getByText("Enter a name.")).toBeVisible();

    await form.getByLabel("Name").fill(name);
    await form.getByLabel("Aliases").fill("E2E-1, e2e-1, ");
    await form.getByLabel("Motivation").fill("Testing");
    await form.getByLabel("Target industries").fill("Finance, finance, Retail");
    await form.getByLabel("Description").fill("Created by the end-to-end tests.");
    await form.getByRole("checkbox", { name: /^NightLoader/ }).check();
    await form.getByRole("checkbox", { name: /^T1566/ }).check();
    await expect(form.getByRole("group", { name: "Malware (1 selected)" })).toBeVisible();
    await form.getByRole("button", { name: "Create threat actor" }).click();

    await expect(page).toHaveURL(/\/threat-actors\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText(name);
    await expect(page.getByText(/Local data: entered by your team/)).toBeVisible();
    await expect(page.getByText("Also known as E2E-1", { exact: true })).toBeVisible();
    await expect(page.getByText("Finance", { exact: true })).toHaveCount(1);
    await expect(page.getByRole("link", { name: "NightLoader" })).toBeVisible();
    await expect(page.getByRole("link", { name: "T1566" })).toBeVisible();
    const detail = page.url();

    // The name is unique, whatever its case.
    await page.goto("/threat-actors/new");
    const again = page.getByRole("form", { name: "New threat actor" });
    await again.getByLabel("Name").fill(name.toUpperCase());
    await again.getByRole("button", { name: "Create threat actor" }).click();
    await expect(page.getByRole("alert").filter({ hasText: /already exists/ })).toBeVisible();

    // Edit: change a field, drop a link, add another.
    await page.goto(detail);
    await page.getByRole("link", { name: "Edit" }).click();
    const edit = page.getByRole("form", { name: "Edit threat actor" });
    await expect(edit.getByLabel("Name")).toHaveValue(name);
    await expect(edit.getByRole("checkbox", { name: /^NightLoader/ })).toBeChecked();
    await edit.getByLabel("Motivation").fill("Testing, edited");
    await edit.getByRole("checkbox", { name: /^NightLoader/ }).uncheck();
    await edit.getByRole("checkbox", { name: /^EmberLock/ }).check();
    await edit.getByRole("button", { name: "Save changes" }).click();

    await expect(page).toHaveURL(detail);
    await expect(page.getByText("Testing, edited")).toBeVisible();
    await expect(page.getByRole("link", { name: "EmberLock" })).toBeVisible();
    await expect(page.getByRole("link", { name: "NightLoader" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "T1566" })).toBeVisible(); // untouched

    // Delete, after a confirmation that can be cancelled.
    await page.getByRole("button", { name: "Delete" }).click();
    const dialog = page.getByRole("dialog", { name: "Delete this threat actor?" });
    await expect(dialog).toContainText(name);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
    await page.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("button", { name: "Delete threat actor" }).click();

    await expect(page).toHaveURL(/\/threat-actors$/);
    await page.getByRole("searchbox", { name: "Search threat actors" }).fill(name);
    await expect(page.getByRole("heading", { name: "No threat actors match" })).toBeVisible();
    // The malware it was linked to is still there.
    await page.goto("/malware");
    await expect(rows(page)).toHaveCount(6);
  });

  test("add, edit and delete a campaign and a malware family", async ({ page }) => {
    const campaign = `E2E Campaign ${stamp}`;
    await page.goto("/campaigns/new");
    const form = page.getByRole("form", { name: "New campaign" });
    await form.getByLabel("Name").fill(campaign);
    await form.getByLabel("Status").selectOption("dormant");
    await form.getByRole("checkbox", { name: "Crimson Harbor" }).check();
    await form.getByRole("button", { name: "Create campaign" }).click();

    await expect(page).toHaveURL(/\/campaigns\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText(campaign);
    await expect(page.getByText("Dormant").first()).toBeVisible();
    await expect(page.getByRole("link", { name: "Crimson Harbor" })).toBeVisible();
    const campaignPage = page.url();

    // The link shows from the actor's side too.
    await page.getByRole("link", { name: "Crimson Harbor" }).click();
    await expect(page.getByRole("link", { name: campaign })).toBeVisible();

    await page.goto(campaignPage);
    await page.getByRole("link", { name: "Edit" }).click();
    const edit = page.getByRole("form", { name: "Edit campaign" });
    await edit.getByLabel("Status").selectOption("concluded");
    await edit.getByRole("checkbox", { name: "Crimson Harbor" }).uncheck();
    await edit.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Concluded").first()).toBeVisible();
    await expect(page.getByText("No threat actors are linked.")).toBeVisible();

    await page.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("button", { name: "Delete campaign" }).click();
    await expect(page).toHaveURL(/\/campaigns$/);
    await expect(rows(page)).toHaveCount(4);

    // Malware.
    const family = `E2E Malware ${stamp}`;
    await page.goto("/malware/new");
    const malwareForm = page.getByRole("form", { name: "New malware family" });
    await malwareForm.getByLabel("Name").fill(family);
    await malwareForm.getByLabel("Type").fill("Loader");
    await malwareForm.getByLabel("Platforms").fill("Windows, windows, Linux");
    await malwareForm.getByRole("checkbox", { name: "Ashen Tide" }).check();
    await malwareForm.getByRole("button", { name: "Create malware family" }).click();

    await expect(page).toHaveURL(/\/malware\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("record-title")).toHaveText(family);
    await expect(page.getByText("Loader").first()).toBeVisible();
    await expect(page.getByText("Windows", { exact: true })).toHaveCount(1);
    await expect(page.getByRole("link", { name: "Ashen Tide" })).toBeVisible();

    await page.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("button", { name: "Delete malware family" }).click();
    await expect(page).toHaveURL(/\/malware$/);
    await expect(rows(page)).toHaveCount(6);
  });

  test("demo intelligence can be edited by an administrator but never relabelled", async ({
    page,
  }) => {
    await page.goto("/threat-actors?q=velvet");
    await rows(page).first().getByRole("link", { name: "Velvet Signal" }).click();
    await expect(page.getByText("This is demo data")).toBeVisible();
    await page.getByRole("link", { name: "Edit" }).click();
    // There is no field for provenance: the form cannot change it.
    await expect(page.getByLabel(/origin|provenance/i)).toHaveCount(0);
    await page.getByRole("link", { name: "Cancel" }).click();
    await expect(page.getByText("This is demo data")).toBeVisible();
  });
});
