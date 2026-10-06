import { createHash } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { adminFetch, STORAGE } from "./support";

const rows = (page: Page) => page.locator("tbody tr");
const stamp = Date.now();

/** Removes what the tests created (by title prefix) with the service role, whatever state they ended in. */
async function cleanUp() {
  // investigations and alerts first: deleting them cascades their checklist items and any
  // response-action log rows, so the catalog actions below are never still referenced.
  for (const table of ["investigations", "alerts", "response_actions"]) {
    await adminFetch(`/rest/v1/${table}?title=like.E2E*`, {
      method: "DELETE",
      headers: { prefer: "return=minimal" },
    });
  }
  await adminFetch("/rest/v1/indicators?value=like.e2e-*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  // detection_rules has no origin/title column the way other record tables do, but the same
  // on-delete-set-null relationship to alerts.matched_rule_id means it can be removed any time.
  await adminFetch("/rest/v1/detection_rules?name=like.E2E*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/wazuh_rules?name=like.E2E*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/siem_rules?name=like.E2E*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/siem_rules?rule_key=eq.e2ebt", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/siem_field_catalog?index_name=eq.e2eidx", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
  await adminFetch("/rest/v1/tags?name=ilike.e2e-*", {
    method: "DELETE",
    headers: { prefer: "return=minimal" },
  });
}

/** Creates an alert through the JSON API as the signed-in user; returns its id. */
async function createAlert(page: Page, title: string) {
  const response = await page.request.post("/api/alerts", { data: { title, severity: "high" } });
  expect(response.status()).toBe(201);
  return (await response.json()).data.id as string;
}

test.afterAll(cleanUp);

test.describe("alerts and investigations (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("both are live in the navigation", async ({ page }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    for (const [label, path] of [
      ["Alerts", "/alerts"],
      ["Investigations", "/investigations"],
    ] as const) {
      await nav.getByRole("link", { name: label }).click();
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page).toHaveTitle(`${label} · ArcRadar`);
      await expect(nav.getByRole("link", { name: label })).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("heading", { level: 1, name: label })).toBeVisible();
    }
  });

  test("the alert list shows provenance on every row and its statistics filter it", async ({
    page,
  }) => {
    await page.goto("/alerts");
    await expect(page.getByText(/^\d+ alerts$/)).toBeVisible();
    const shown = await rows(page).count();
    expect(shown).toBeGreaterThan(0);
    await expect(page.getByText("Demo data").filter({ visible: true })).toHaveCount(shown);

    const stats = page.getByRole("region", { name: "Alert statistics" });
    await stats.getByRole("link", { name: /^Unassigned/ }).click();
    await expect(page).toHaveURL(/assignee=none/);
    await expect(stats.getByRole("link", { name: /^Unassigned/ })).toHaveAttribute(
      "aria-current",
      "true",
    );

    await stats.getByRole("link", { name: /^New\b/ }).click();
    await expect(page).toHaveURL(/status=new/);
    await expect(page).not.toHaveURL(/assignee=/);
    await expect(stats.getByRole("link", { name: /^New\b/ })).toHaveAttribute(
      "aria-current",
      "true",
    );

    await stats.getByRole("link", { name: /^All alerts/ }).click();
    await expect(page).toHaveURL(/\/alerts$/);
  });

  test("searching and sorting the alert list are recorded in the address", async ({ page }) => {
    await page.goto("/alerts");
    await page.getByRole("searchbox", { name: "Search alerts" }).fill("beacon");
    await expect(page).toHaveURL(/[?&]q=beacon/);
    await expect(page.getByText(/alerts? match(es)?$/)).toBeVisible();
    for (const row of await rows(page).all()) await expect(row).toContainText(/beacon/i);

    await page
      .getByRole("columnheader", { name: /Severity/ })
      .getByRole("link")
      .click();
    await expect(page).toHaveURL(/sort=severity&order=asc/);
    await expect(page.getByRole("columnheader", { name: /Severity/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );

    await page.getByRole("searchbox", { name: "Search alerts" }).fill("zzz-nothing-matches");
    await expect(page.getByRole("heading", { name: "No alerts match" })).toBeVisible();
  });

  test("a page past the last one is an empty page with a way back", async ({ page }) => {
    await page.goto("/alerts?page=999");
    await expect(page.getByRole("heading", { name: "That page is past the end" })).toBeVisible();
    await page.getByRole("link", { name: "Go to the last page" }).click();
    await expect(rows(page).first()).toBeVisible();
  });

  test("an alert opens read-only: provenance, timeline, no workflow, no delete", async ({
    page,
  }) => {
    await page.goto("/alerts?q=beacon");
    await rows(page).first().getByRole("link").first().click();
    await expect(page).toHaveURL(/\/alerts\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("alert-title")).toContainText(/beacon/i);
    await expect(page.getByText("This is demo data")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Related indicator" })).toBeVisible();
    await expect(page.getByTestId("alert-actions")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
  });

  test("viewers cannot create alerts or investigations", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.getByRole("link", { name: "New alert" })).toHaveCount(0);
    await page.goto("/alerts/new");
    await expect(page.getByRole("heading", { name: "You can't create alerts" })).toBeVisible();

    await page.goto("/investigations");
    await expect(page.getByRole("link", { name: "New investigation" })).toHaveCount(0);
    await page.goto("/investigations/new");
    await expect(
      page.getByRole("heading", { name: "You can't open investigations" }),
    ).toBeVisible();
  });

  test("the investigation list has statistics, search and filters", async ({ page }) => {
    await page.goto("/investigations");
    await expect(page.getByText(/^\d+ investigations$/)).toBeVisible();
    await expect(page.getByText("Demo data").filter({ visible: true })).not.toHaveCount(0);

    const stats = page.getByRole("region", { name: "Investigation statistics" });
    await stats.getByRole("link", { name: /^Investigating/ }).click();
    await expect(page).toHaveURL(/status=investigating/);
    await expect(rows(page).first()).toBeVisible();

    await page.getByRole("searchbox", { name: "Search investigations" }).fill("harbor");
    await expect(page).toHaveURL(/q=harbor/);
    await expect(rows(page).first()).toContainText("Harbor");

    await page.getByRole("combobox", { name: "Priority", exact: true }).selectOption("critical");
    await expect(page).toHaveURL(/priority=critical/);
    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await expect(page).toHaveURL(/\/investigations$/);
  });

  test("a demo investigation opens read-only with its attachments and timeline", async ({
    page,
  }) => {
    await page.goto("/investigations?q=Harbor%20Lights%20C2");
    await rows(page).first().getByRole("link").first().click();
    await expect(page.getByTestId("investigation-title")).toHaveText(
      "Harbor Lights C2 infrastructure",
    );
    await expect(page.getByText("This is demo data")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Indicators" })).toBeVisible();
    await expect(
      page.getByRole("list", { name: "Attached indicators" }).getByText("198.51.100.23"),
    ).toBeVisible();
    await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
    await expect(page.getByText("Investigation opened")).toBeVisible();

    // Nothing to change for a viewer.
    await expect(page.getByTestId("investigation-controls")).toHaveCount(0);
    await expect(page.getByLabel("Add a note")).toHaveCount(0);
    await expect(page.getByLabel("Attach an indicator")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
  });
});

test.describe("the alert workflow (analyst)", () => {
  test.use({ storageState: STORAGE.analyst });
  test.setTimeout(90_000);

  test("create, acknowledge, resolve, reopen, close as a false positive, assign", async ({
    page,
  }) => {
    const title = `E2E alert ${stamp}`;
    await page.goto("/alerts");
    await page.getByRole("link", { name: "New alert" }).click();
    const form = page.getByRole("form", { name: "New alert" });
    await expect(form).toBeVisible();

    // The form checks input before it asks the server.
    await form.getByRole("button", { name: "Create alert" }).click();
    await expect(form.getByText("Enter a title.")).toBeVisible();

    await form.getByLabel("Title").fill(title);
    await form.getByLabel("Severity").selectOption("high");
    await form.getByLabel("Description").fill("Created by the end-to-end tests.");
    await form.getByRole("button", { name: "Create alert" }).click();

    await expect(page).toHaveURL(/\/alerts\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("alert-title")).toHaveText(title);
    await expect(page.getByTestId("alert-status")).toHaveText("New");
    await expect(page.getByText(/Local data: entered by your team/)).toBeVisible();
    await expect(page.getByTestId("alert-assignee")).toHaveText("Nobody");
    // An analyst may work the alert but not delete it.
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);

    const actions = page.getByTestId("alert-actions");
    const timeline = page.locator("ol");

    await actions.getByRole("button", { name: "Acknowledge" }).click();
    await expect(page.getByTestId("alert-status")).toHaveText("Acknowledged");
    await expect(page.getByTestId("alert-assignee")).not.toHaveText("Nobody"); // taken by the analyst
    await expect(timeline.getByText("Acknowledged", { exact: true })).toBeVisible();

    await actions.getByRole("button", { name: "Resolve" }).click();
    await expect(page.getByTestId("alert-status")).toHaveText("Resolved");
    await expect(timeline.getByText("Closed as resolved")).toBeVisible();
    // Only the moves the lifecycle allows are offered.
    await expect(actions.getByRole("button", { name: "Reopen" })).toBeVisible();
    await expect(actions.getByRole("button", { name: "Acknowledge" })).toHaveCount(0);
    await expect(actions.getByRole("button", { name: "Resolve" })).toHaveCount(0);

    await actions.getByRole("button", { name: "Reopen" }).click();
    await expect(page.getByTestId("alert-status")).toHaveText("Investigating");
    await expect(actions.getByRole("button", { name: "Reopen" })).toHaveCount(0);

    await actions.getByRole("button", { name: "Mark as false positive" }).click();
    await expect(page.getByTestId("alert-status")).toHaveText("False positive");
    await expect(timeline.getByText("Closed as false positive")).toBeVisible();

    // Everyone who may work alerts can be given one, each with their role beside the name:
    // the administrator, the SOC L2 analyst and the SOC L1 analyst, but never a viewer.
    const assignees = actions.getByLabel("Assigned to").getByRole("option");
    await expect(assignees.filter({ hasText: "(Admin)" })).toHaveCount(1);
    await expect(assignees.filter({ hasText: "(SOC L2)" })).toHaveCount(1);
    await expect(assignees.filter({ hasText: "Demo L1 Analyst (SOC L1)" })).toHaveCount(1);
    await expect(assignees.filter({ hasText: "Viewer" })).toHaveCount(0);
    await actions.getByLabel("Assigned to").selectOption({ label: "Demo L1 Analyst (SOC L1)" });
    await expect(page.getByTestId("alert-assignee")).toHaveText("Demo L1 Analyst");

    await actions.getByLabel("Assigned to").selectOption("");
    await expect(page.getByTestId("alert-assignee")).toHaveText("Nobody");
    await actions.getByRole("button", { name: "Assign to me" }).click();
    await expect(page.getByTestId("alert-assignee")).not.toHaveText("Nobody");

    // The list shows the new state too.
    await page.goto(`/alerts?q=${encodeURIComponent(title)}`);
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first()).toContainText("False positive");
    await expect(rows(page).first()).toContainText("Local");
  });

  test("opening an investigation from an alert starts work on it", async ({ page }) => {
    const title = `E2E alert case ${stamp}`;
    const alertId = await createAlert(page, title);

    await page.goto(`/alerts/${alertId}`);
    await expect(page.getByTestId("alert-status")).toHaveText("New");
    await page.getByRole("button", { name: "Open an investigation" }).click();

    await expect(page).toHaveURL(/\/investigations\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("investigation-title")).toHaveText(title);
    await expect(page.getByTestId("investigation-status")).toHaveText("Open");
    const attached = page.getByRole("list", { name: "Attached alerts" });
    await expect(attached.getByText(title)).toBeVisible();
    await expect(attached.getByText("Investigating")).toBeVisible();

    // From the alert, the investigation is one click away.
    await attached.getByRole("link", { name: title }).click();
    await expect(page.getByTestId("alert-status")).toHaveText("Investigating");
    await expect(page.getByRole("link", { name: title }).last()).toHaveAttribute(
      "href",
      /\/investigations\/[0-9a-f-]{36}$/,
    );
  });
});

test.describe("the investigation workflow (analyst)", () => {
  test.use({ storageState: STORAGE.analyst });
  test.setTimeout(120_000);

  test("open a case, work it, attach things, take notes, add evidence, close it", async ({
    page,
  }) => {
    const title = `E2E case ${stamp}`;
    const alertTitle = `E2E alert attach ${stamp}`;
    await createAlert(page, alertTitle);

    await page.goto("/investigations");
    await page.getByRole("link", { name: "New investigation" }).click();
    const form = page.getByRole("form", { name: "New investigation" });
    await expect(form).toBeVisible();
    await form.getByRole("button", { name: "Open investigation" }).click();
    await expect(form.getByText("Enter a title.")).toBeVisible();

    await form.getByLabel("Title").fill(title);
    await form.getByLabel("Description").fill("Created by the end-to-end tests.");
    await form.getByLabel("Priority").selectOption("high");
    await form.getByLabel("Tags").fill("e2e-case");
    await form.getByLabel("Tags").press("Enter");
    await form.getByRole("button", { name: "Open investigation" }).click();

    await expect(page).toHaveURL(/\/investigations\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("investigation-title")).toHaveText(title);
    await expect(page.getByTestId("investigation-status")).toHaveText("Open");
    await expect(page.getByText(/Local data: entered by your team/)).toBeVisible();
    await expect(page.getByText("e2e-case").first()).toBeVisible();
    await expect(page.getByTestId("investigation-analyst")).not.toHaveText("Unassigned");
    await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0); // administrators only

    const timeline = page.getByRole("list", { name: "Timeline" });
    const controls = page.getByTestId("investigation-controls");

    await test.step("status, priority and analyst leave lines in the history", async () => {
      await controls.getByLabel("Status").selectOption("investigating");
      await expect(page.getByTestId("investigation-status")).toHaveText("Investigating");
      await expect(timeline.getByText("Status changed from Open to Investigating.")).toBeVisible();

      await controls.getByLabel("Priority").selectOption("critical");
      await expect(timeline.getByText("Priority changed from High to Critical.")).toBeVisible();

      await controls.getByLabel("Analyst").selectOption("");
      await expect(page.getByTestId("investigation-analyst")).toHaveText("Unassigned");
      await expect(timeline.getByText("Unassigned.", { exact: true })).toBeVisible();
    });

    await test.step("the title, description and tags can be edited", async () => {
      await controls.getByRole("button", { name: "Edit title, description and tags" }).click();
      await controls.getByLabel("Title").fill(`${title} (edited)`);
      await controls.getByRole("button", { name: "Save changes" }).click();
      await expect(page.getByTestId("investigation-title")).toHaveText(`${title} (edited)`);
    });

    await test.step("notes: add, edit, and see them on the timeline", async () => {
      await page.getByLabel("Add a note").fill("Confirmed in the proxy logs.");
      await page.getByRole("button", { name: "Add note" }).click();
      const notes = page.getByRole("list", { name: "Notes" });
      await expect(notes.getByText("Confirmed in the proxy logs.")).toBeVisible();
      await expect(timeline.getByText("Note added")).toBeVisible();

      await notes.getByRole("button", { name: "Edit this note" }).click();
      await page.getByLabel("Edit note").fill("Confirmed in the proxy and DNS logs.");
      await page.getByRole("button", { name: "Save note" }).click();
      await expect(notes.getByText("Confirmed in the proxy and DNS logs.")).toBeVisible();
      await expect(notes.getByText("(edited)")).toBeVisible();
    });

    await test.step("evidence: it needs a location, and references are listed", async () => {
      await page.getByRole("button", { name: "Add evidence" }).click();
      await expect(page.getByText("Say where the evidence is")).toBeVisible();

      await page.getByLabel("Title").last().fill("Proxy export");
      await page.getByLabel("Location").fill("ticket #4711");
      await page.getByRole("button", { name: "Add evidence" }).click();
      const evidence = page.getByRole("list", { name: "Evidence" });
      await expect(evidence.getByText("Proxy export")).toBeVisible();
      await expect(evidence.getByText("ticket #4711")).toBeVisible();
      await expect(timeline.getByText("Evidence added")).toBeVisible();

      await evidence.getByRole("button", { name: "Remove Proxy export" }).click();
      await expect(evidence).toHaveCount(0);
    });

    await test.step("an indicator is found by search, attached and detached", async () => {
      const attachedIndicators = page.getByRole("list", { name: "Attached indicators" });
      await page.getByLabel("Attach an indicator").fill("harbor-lights-c2");
      await page.getByRole("button", { name: "Domain harbor-lights-c2.example" }).click();
      await expect(attachedIndicators.getByText("harbor-lights-c2.example")).toBeVisible();
      await expect(attachedIndicators.getByText("Demo data")).toBeVisible();
      await expect(timeline.getByText("Indicator attached")).toBeVisible();

      await attachedIndicators
        .getByRole("button", { name: "Detach harbor-lights-c2.example", exact: true })
        .click();
      await expect(attachedIndicators).toHaveCount(0);
    });

    await test.step("an alert is attached, and starts to be worked", async () => {
      await page.getByLabel("Attach an alert").fill(alertTitle);
      await page.getByRole("button", { name: new RegExp(alertTitle) }).click();
      const attachedAlerts = page.getByRole("list", { name: "Attached alerts" });
      await expect(attachedAlerts.getByText(alertTitle)).toBeVisible();
      await expect(attachedAlerts.getByText("Investigating")).toBeVisible();
      await expect(timeline.getByText("Alert attached")).toBeVisible();
    });

    await test.step("closing it stamps a closing date; reopening clears it", async () => {
      await controls.getByLabel("Status").selectOption("closed");
      await expect(page.getByTestId("investigation-status")).toHaveText("Closed");
      await expect(page.locator("dt", { hasText: /^Closed$/ })).toBeVisible();
      await expect(
        timeline.getByText("Status changed from Investigating to Closed."),
      ).toBeVisible();

      await controls.getByLabel("Status").selectOption("investigating");
      await expect(page.getByTestId("investigation-status")).toHaveText("Investigating");
      await expect(page.locator("dt", { hasText: /^Closed$/ })).toHaveCount(0);
    });

    await test.step("the list shows it with its attachments", async () => {
      await page.goto(`/investigations?q=${encodeURIComponent(`${title} (edited)`)}`);
      await expect(rows(page)).toHaveCount(1);
      await expect(rows(page).first()).toContainText("Local");
      await expect(rows(page).first()).toContainText("Critical");
    });
  });
});

test.describe("deleting (administrator)", () => {
  test.use({ storageState: STORAGE.admin });

  test("an administrator deletes an alert after confirming", async ({ page }) => {
    const title = `E2E alert delete ${stamp}`;
    const alertId = await createAlert(page, title);
    await page.goto(`/alerts/${alertId}`);

    await page.getByRole("button", { name: "Delete" }).click();
    const dialog = page.getByRole("dialog", { name: "Delete this alert?" });
    await expect(dialog).toBeVisible();
    // Cancelling changes nothing.
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(new RegExp(alertId));

    await page.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("button", { name: "Delete alert" }).click();
    await expect(page).toHaveURL(/\/alerts$/);
    await page.goto(`/alerts?q=${encodeURIComponent(title)}`);
    await expect(page.getByRole("heading", { name: "No alerts match" })).toBeVisible();
    await page.goto(`/alerts/${alertId}`);
    await expect(page.getByRole("heading", { name: /not found/i })).toBeVisible();
  });

  test("an administrator deletes an investigation, and its attachments stay", async ({ page }) => {
    const title = `E2E case delete ${stamp}`;
    const alertId = await createAlert(page, `E2E alert stays ${stamp}`);
    const created = await page.request.post("/api/investigations", {
      data: { title, alert_ids: [alertId] },
    });
    expect(created.status()).toBe(201);
    const id = (await created.json()).data.id as string;

    await page.goto(`/investigations/${id}`);
    await page.getByRole("button", { name: "Delete" }).click();
    await expect(page.getByRole("dialog", { name: "Delete this investigation?" })).toBeVisible();
    await page.getByRole("button", { name: "Delete investigation" }).click();
    await expect(page).toHaveURL(/\/investigations$/);

    await page.goto(`/investigations?q=${encodeURIComponent(title)}`);
    await expect(page.getByRole("heading", { name: "No investigations match" })).toBeVisible();
    await page.goto(`/alerts/${alertId}`);
    await expect(page.getByTestId("alert-title")).toContainText("E2E alert stays");
  });
});

test.describe("AI analysis on the alert page", () => {
  test.use({ storageState: STORAGE.analyst });

  // No AI provider key exists in this local test environment, the same caveat the live intel
  // providers carry: only the "not configured" state is exercised here, never a real provider call.
  test("an analyst sees why the AI actions are unavailable, and can still read an empty history", async ({
    page,
  }) => {
    const alertId = await createAlert(page, `E2E ai alert ${stamp}`);
    await page.goto(`/alerts/${alertId}`);

    const panel = page.getByTestId("ai-analysis-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByText("No AI provider is configured.")).toBeVisible();
    await expect(panel.getByRole("link", { name: "Integrations" })).toHaveAttribute(
      "href",
      "/integrations",
    );
    await expect(
      panel.getByText("No AI analysis has been generated for this alert yet."),
    ).toBeVisible();

    const denied = await page.request.post(`/api/alerts/${alertId}/ai`, {
      data: { kind: "threat_summary" },
    });
    expect(denied.status()).toBe(503);
  });

  test("a viewer with no AI permission and no existing analysis sees no AI card at all", async ({
    page,
    browser,
    baseURL,
  }) => {
    const alertId = await createAlert(page, `E2E ai viewer alert ${stamp}`);
    const context = await browser.newContext({ storageState: STORAGE.viewer, baseURL });
    const viewerPage = await context.newPage();
    await viewerPage.goto(`/alerts/${alertId}`);
    await expect(viewerPage.getByTestId("alert-title")).toBeVisible();
    await expect(viewerPage.getByTestId("ai-analysis-panel")).toHaveCount(0);
    await context.close();
  });
});

test.describe("Response orchestration and checklists (Phase 9)", () => {
  test.use({ storageState: STORAGE.analyst });

  test("a catalog action is recommended on an alert and moved through the workflow", async ({
    page,
  }) => {
    const title = `E2E orchestrate action ${stamp}`;
    const created = await page.request.post("/api/response-actions", {
      data: { title, category: "containment" },
    });
    expect(created.status()).toBe(201);

    const alertId = await createAlert(page, `E2E orchestration alert ${stamp}`);
    await page.goto(`/alerts/${alertId}`);

    const panel = page.getByTestId("response-actions-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByText("No response actions recommended yet.")).toBeVisible();

    await panel.getByLabel("Recommend an action").selectOption({ label: title });
    await panel.getByRole("button", { name: "Recommend" }).click();

    const entry = panel.locator("li", { hasText: title });
    await expect(entry).toBeVisible();
    await expect(entry.getByText("Recommended", { exact: true })).toBeVisible();

    await entry.getByRole("button", { name: "Acknowledged" }).click();
    await expect(entry.getByText("Acknowledged", { exact: true })).toBeVisible();
    await entry.getByRole("button", { name: "Completed" }).click();
    await expect(entry.getByText("Completed", { exact: true })).toBeVisible();
    // A completed action has no further move: neither button remains.
    await expect(entry.getByRole("button")).toHaveCount(0);
  });

  test("the response-action catalog page lists, adds and deletes an entry", async ({ page }) => {
    const title = `E2E catalog action ${stamp}`;
    await page.goto("/response-actions");
    await page.getByLabel("Title").fill(title);
    await page.getByLabel("Category (optional)").fill("eradication");
    await page.getByRole("button", { name: "Add action" }).click();

    const card = page.locator("li", { hasText: title });
    await expect(card).toBeVisible();
    await expect(card.getByText("eradication")).toBeVisible();

    await card.getByRole("button", { name: `Delete ${title}` }).click();
    await expect(card).toHaveCount(0);
  });

  test("an analyst adds, checks off and removes a checklist item by hand, and sees the AI state", async ({
    page,
  }) => {
    const created = await page.request.post("/api/investigations", {
      data: { title: `E2E checklist case ${stamp}` },
    });
    expect(created.status()).toBe(201);
    const investigationId = (await created.json()).data.id as string;
    await page.goto(`/investigations/${investigationId}`);

    const panel = page.getByTestId("checklist-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByText("No AI provider is configured.")).toBeVisible();
    await expect(panel.getByText("No checklist items yet.")).toBeVisible();

    const itemText = "Pull DNS logs for the affected host";
    await panel.getByLabel("Add an item").fill(itemText);
    await panel.getByRole("button", { name: "Add" }).click();

    const checkbox = panel.getByRole("checkbox", { name: itemText });
    await expect(checkbox).toBeVisible();
    await expect(checkbox).not.toBeChecked();
    await checkbox.check();
    await expect(checkbox).toBeChecked();

    await panel.getByRole("button", { name: `Remove "${itemText}"` }).click();
    await expect(panel.getByText("No checklist items yet.")).toBeVisible();
  });

  test("an indicator's verdict recommendation panel explains why AI is unavailable", async ({
    page,
  }) => {
    const created = await page.request.post("/api/indicators", {
      data: { type: "domain", value: `e2e-verdict-${stamp}.example` },
    });
    expect(created.status()).toBe(201);
    const indicatorId = (await created.json()).data.id as string;
    await page.goto(`/indicators/${indicatorId}`);

    const panel = page.getByTestId("verdict-recommendation-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByText("No AI provider is configured.")).toBeVisible();
    await expect(panel.getByText("No AI recommendation yet.")).toBeVisible();
  });
});

test.describe("Detection rules and alert deduplication (Phase 10)", () => {
  test.describe("the detection-rules page (administrator)", () => {
    test.use({ storageState: STORAGE.admin });

    test("an admin adds a rule, sees it trace itself on a matching alert, disables and deletes it", async ({
      page,
    }) => {
      const ruleId = String(100000 + (stamp % 899999));
      const ruleName = `E2E rule ${stamp}`;
      const marker = `e2edr${stamp}`;

      await page.goto("/detection-rules?tab=severity");
      await page.getByLabel("Rule id").fill(ruleId);
      await page.getByLabel("Name").fill(ruleName);
      // The condition builder defaults to field "Title" / comparison "contains".
      await page.getByLabel("Condition 1 value").fill(marker);
      await page.getByLabel("Raise severity to").selectOption({ label: "Critical" });
      await page.getByRole("button", { name: "Add rule" }).click();

      const card = page.locator("li", { hasText: ruleName });
      await expect(card).toBeVisible();
      await expect(card.getByText("Raises to Critical")).toBeVisible();

      const alertId = await createAlert(page, `E2E ${marker} matches a rule`);
      await page.goto(`/alerts/${alertId}`);
      await expect(page.getByTestId("alert-matched-rule")).toContainText(ruleName);

      await page.goto("/detection-rules?tab=severity");
      await card.getByRole("checkbox").uncheck();
      await expect(card.getByText("Disabled")).toBeVisible();

      await card.getByRole("button", { name: `Delete ${ruleName}` }).click();
      await expect(card).toHaveCount(0);
    });

    test("an admin drafts a Wazuh rule, reads its XML, edits it, rejects it and deletes it", async ({
      page,
    }) => {
      const name = `E2E wazuh rule ${stamp}`;
      const renamed = `${name} edited`;

      await page.goto("/detection-rules");
      await expect(page.getByRole("link", { name: "Wazuh rules" })).toHaveAttribute(
        "aria-current",
        "page",
      );
      await page.getByRole("button", { name: "Manual rule" }).click();
      await page.getByLabel("Name", { exact: true }).fill(name);
      await page.getByLabel("Condition 1 value").fill(`e2ewz${stamp}`);
      await page.getByRole("button", { name: "Save as draft" }).click();

      const card = page.locator("li", { hasText: name });
      await expect(card).toBeVisible();
      await expect(card.getByText("Draft", { exact: true })).toBeVisible();
      await expect(card.getByText("Manual", { exact: true })).toBeVisible();
      await expect(card.locator("pre")).toContainText("<if_group>windows</if_group>");
      await expect(card.locator("pre")).toContainText(`e2ewz${stamp}`);
      // Nothing is connected to GitHub in the test environment: the button is there but disabled.
      await expect(page.getByText("GitHub is not connected")).toBeVisible();
      await expect(card.getByRole("button", { name: "Send to GitHub" })).toBeDisabled();

      await card.getByRole("button", { name: "Edit", exact: true }).click();
      await card.getByLabel("Name", { exact: true }).fill(renamed);
      await card.getByRole("button", { name: "Save changes" }).click();
      const edited = page.locator("li", { hasText: renamed });
      await expect(edited).toBeVisible();

      await edited.getByRole("button", { name: "Reject", exact: true }).click();
      await edited.getByLabel("Reason (optional)").fill("e2e");
      await edited.getByRole("button", { name: "Confirm reject" }).click();
      await expect(edited.getByText("Rejected", { exact: true })).toBeVisible();
      await expect(edited.getByText("rejected: e2e")).toBeVisible();

      await edited.getByRole("button", { name: `Delete ${renamed}` }).click();
      await expect(edited).toHaveCount(0);
    });

    test("a repeating rule (5 in 5 minutes, same address) is saved without any condition", async ({
      page,
    }) => {
      const name = `E2E repeating rule ${stamp}`;
      await page.goto("/detection-rules");
      await page.getByRole("button", { name: "Manual rule" }).click();
      await page.getByLabel("Name", { exact: true }).fill(name);
      await page.getByLabel("Group", { exact: true }).fill("authentication_failed");
      await page.getByLabel("Only when it repeats").check();
      await page.getByLabel("Remove condition 1").click();
      await page.getByLabel("Same value in (optional)").fill("win.eventdata.ipAddress");
      await page.getByRole("button", { name: "Save as draft" }).click();

      const card = page.locator("li", { hasText: name });
      await expect(card).toBeVisible();
      await expect(card.getByText("5× in 5 min")).toBeVisible();
      await expect(card.locator("pre")).toContainText('frequency="5" timeframe="300"');
      await expect(card.locator("pre")).toContainText(
        "<if_matched_group>authentication_failed</if_matched_group>",
      );
      await card.getByRole("button", { name: `Delete ${name}` }).click();
      await expect(card).toHaveCount(0);
    });

    test("an unsafe pattern is refused on the form", async ({ page }) => {
      await page.goto("/detection-rules");
      await page.getByRole("button", { name: "Manual rule" }).click();
      await page.getByLabel("Name", { exact: true }).fill(`E2E unsafe ${stamp}`);
      await page.getByLabel("Condition 1 comparison").selectOption({ label: "matches regex" });
      await page.getByLabel("Condition 1 value").fill("(a+)+");
      await page.getByRole("button", { name: "Save as draft" }).click();
      await expect(page.getByText("can make matching very slow")).toBeVisible();
    });

    test("an admin drafts a Splunk rule, reads its generated search, edits, rejects and deletes it", async ({
      page,
    }) => {
      const name = `E2E splunk rule ${stamp}`;
      const renamed = `${name} edited`;

      await page.goto("/detection-rules?tab=splunk");
      await expect(page.getByRole("link", { name: "Splunk rules" })).toHaveAttribute(
        "aria-current",
        "page",
      );
      await page.getByRole("button", { name: "Manual rule" }).click();
      await page.getByLabel("Name", { exact: true }).fill(name);
      await page.getByLabel("Condition 1 value").fill("4625");
      await page.getByLabel("Only when it repeats").check();
      await page.getByLabel("Count per (optional)").fill("Source_Network_Address");
      await page.getByRole("button", { name: "Save as draft" }).click();

      const card = page.locator("li", { hasText: name });
      await expect(card).toBeVisible();
      await expect(card.getByText("Draft", { exact: true })).toBeVisible();
      await expect(card.getByText("5× in 5 min")).toBeVisible();
      await expect(card.locator("pre")).toContainText(
        'regex EventCode="(?i)^4625$" | stats count by Source_Network_Address | where count >= 5',
      );
      await expect(card.locator("pre")).not.toContainText("outputlookup");
      await expect(page.getByText("GitHub is not connected")).toBeVisible();
      await expect(card.getByRole("button", { name: "Send to GitHub" })).toBeDisabled();

      await card.getByRole("button", { name: "Edit", exact: true }).click();
      await card.getByLabel("Name", { exact: true }).fill(renamed);
      await card.getByLabel("Severity").selectOption({ label: "Critical" });
      await card.getByRole("button", { name: "Save changes" }).click();
      const edited = page.locator("li", { hasText: renamed });
      await expect(edited).toBeVisible();
      await expect(edited.locator("pre")).toContainText("alert.severity = 5");

      await edited.getByRole("button", { name: "Reject", exact: true }).click();
      await edited.getByLabel("Reason (optional)").fill("e2e");
      await edited.getByRole("button", { name: "Confirm reject" }).click();
      await expect(edited.getByText("Rejected", { exact: true })).toBeVisible();

      await edited.getByRole("button", { name: `Delete ${renamed}` }).click();
      await expect(edited).toHaveCount(0);
    });

    test("the Splunk form offers the fields Splunk reported and warns about one it has never seen", async ({
      page,
    }) => {
      await adminFetch("/rest/v1/rpc/sync_field_catalog", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          p_siem: "splunk",
          p_sources: [
            {
              index: "e2eidx",
              sourcetype: "e2e:logs",
              window_hours: 24,
              events_sampled: 100,
              fields: [
                { name: "e2e_status", count: 80, distinct: 3, values: ["failed", "ok"] },
                { name: "e2e_user", count: 100, distinct: 9, values: ["amy"] },
              ],
            },
          ],
        }),
      });
      await page.goto("/detection-rules?tab=splunk");
      await page.getByRole("button", { name: "Manual rule" }).click();
      await expect(
        page.getByText("Index, sourcetype and fields below come from what Splunk reported"),
      ).toBeVisible();
      await page.getByLabel("Index", { exact: true }).fill("e2eidx");
      await page.getByLabel("Sourcetype (optional)").fill("e2e:logs");
      await page.getByLabel("Condition 1 field").fill("e2e_status");
      await expect(page.getByText("Seen in 80% of events · examples: failed, ok")).toBeVisible();
      await page.getByLabel("Condition 1 field").fill("e2e_statuss");
      await expect(page.getByText("Not seen in this data in the last 24 h")).toBeVisible();
    });

    test("a rule pushed in test mode shows what Splunk found on past data, and a stale result is flagged", async ({
      page,
    }) => {
      const search = 'index=main | regex EventCode="(?i)^4625$"';
      const digest = createHash("sha256").update(search).digest("hex");
      await adminFetch("/rest/v1/siem_rules", {
        method: "POST",
        headers: { prefer: "return=minimal" },
        body: JSON.stringify({
          siem: "splunk",
          rule_key: "e2ebt",
          name: `E2E backtest rule ${stamp}`,
          severity: "high",
          mode: "test",
          status: "pushed",
          github_path: "splunk/arcradar_e2ebt.conf",
          source: "manual",
          origin: "local",
          spec: {
            index: "main",
            sourcetype: null,
            conditions: [{ field: "EventCode", op: "equals", value: "4625" }],
            threshold: null,
            schedule: "every_5_minutes",
          },
        }),
      });
      await adminFetch("/rest/v1/rpc/sync_rule_backtests", {
        method: "POST",
        body: JSON.stringify({
          p_siem: "splunk",
          p_results: [
            {
              rule_key: "e2ebt",
              window_hours: 24,
              kind: "events",
              matches: 7,
              scanned: 513,
              sample: [{ time: "2026-10-06T10:00:00Z", group: { EventCode: "4625" } }],
              search_sha256: digest,
            },
            {
              rule_key: "e2ebt",
              window_hours: 168,
              kind: "events",
              matches: 12,
              scanned: 2000,
              sample: [],
              search_sha256: "b".repeat(64),
            },
          ],
        }),
      });
      await page.goto("/detection-rules?tab=splunk");
      const card = page.locator("li", { hasText: `E2E backtest rule ${stamp}` });
      await expect(card.getByText("Test mode · not alerting")).toBeVisible();
      await expect(card.locator("pre")).toContainText("enableSched = 0");
      const panel = card.getByTestId("backtest");
      await expect(panel).toContainText(
        "Last 24 hours: would have fired for 7 events out of 513 events",
      );
      await expect(panel).toContainText("latest at 2026-10-06 10:00 UTC");
      // the 7-day result was measured for another search: flagged, the 24 h one is not
      await expect(panel).toContainText("Last 7 days: would have fired for 12 events");
      await expect(panel.getByText("out of date: the rule changed after this test")).toHaveCount(1);
      await expect(card.getByRole("button", { name: "Go live" })).toBeDisabled();
      await expect(card.getByRole("button", { name: "Push as test" })).toHaveCount(0);
      // a rule that is on GitHub is withdrawn, not rejected; the confirmation explains what happens
      await card.getByRole("button", { name: "Withdraw" }).click();
      await expect(
        card.getByText("Withdrawing deletes its file from the repository"),
      ).toBeVisible();
      await expect(card.getByRole("button", { name: "Confirm withdraw" })).toBeDisabled();
    });

    test("a Splunk field that is not a plain name is refused on the form", async ({ page }) => {
      await page.goto("/detection-rules?tab=splunk");
      await page.getByRole("button", { name: "Manual rule" }).click();
      await page.getByLabel("Name", { exact: true }).fill(`E2E splunk bad ${stamp}`);
      await page.getByLabel("Condition 1 field").fill("a | outputlookup x");
      await page.getByLabel("Condition 1 value").fill("1");
      await page.getByRole("button", { name: "Save as draft" }).click();
      await expect(page.getByText("Use a Splunk field name")).toBeVisible();
    });

    test("a viewer cannot reach the page at all", async ({ browser, baseURL }) => {
      const context = await browser.newContext({ storageState: STORAGE.viewer, baseURL });
      const viewerPage = await context.newPage();
      await viewerPage.goto("/detection-rules");
      await expect(viewerPage.getByText("You don't have access to this page")).toBeVisible();
      await context.close();
    });
  });

  test.describe("duplicates on the alert page (analyst)", () => {
    test.use({ storageState: STORAGE.analyst });

    test("a repeated alert links to its primary; each side says so", async ({ page }) => {
      const title = `E2E dup pair ${stamp}`;
      const firstId = await createAlert(page, title);
      const secondId = await createAlert(page, title);

      await page.goto(`/alerts/${firstId}`);
      await expect(page.getByText("Duplicates (1)")).toBeVisible();

      await page.goto(`/alerts/${secondId}`);
      await expect(page.getByText("This is a duplicate of")).toBeVisible();
      await page.getByRole("link", { name: title }).click();
      await expect(page).toHaveURL(new RegExp(`/alerts/${firstId}$`));
    });
  });
});
