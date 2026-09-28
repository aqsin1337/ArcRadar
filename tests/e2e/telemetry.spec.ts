import { expect, test, type Page } from "@playwright/test";
import { cleanTelemetry, ingest, STORAGE, wazuhAlerts } from "./support";

const rows = (page: Page) => page.locator("tbody tr");
const marker = `E2E-TEL-${Date.now()}`;
const card = (page: Page, source: string, status?: string) =>
  page.locator(
    `[data-testid="source-card"][data-source="${source}"]${status ? `[data-status="${status}"]` : ""}`,
  );

test.afterAll(() => cleanTelemetry(marker));

test.describe("the telemetry page (viewer)", () => {
  test.use({ storageState: STORAGE.viewer });

  test("is live in the navigation, with sources, assets and events", async ({ page }) => {
    await page.goto("/dashboard");
    const nav = page.getByRole("navigation", { name: "Main" });
    await nav.getByRole("link", { name: "Telemetry" }).click();
    await expect(page).toHaveURL(/\/telemetry$/);
    await expect(page).toHaveTitle("Telemetry · ArcRadar");
    await expect(nav.getByRole("link", { name: "Telemetry" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(page.getByRole("heading", { level: 1, name: "Telemetry" })).toBeVisible();
    for (const section of ["Sources", "Assets", "Events"]) {
      await expect(page.getByRole("heading", { level: 2, name: section })).toBeVisible();
    }
  });

  test("the Wazuh connector is always listed, and the demo feeds say they are not live", async ({
    page,
  }) => {
    await page.goto("/telemetry");
    await expect(card(page, "wazuh").first()).toBeVisible();

    const demo = page.locator('[data-testid="source-card"][data-status="demo"]');
    await expect(demo.first()).toBeVisible();
    for (const one of await demo.all()) {
      await expect(one).toContainText("Demo feed");
      await expect(one).toContainText("Demo data");
      await expect(one).toContainText("Sample data, not a live connection");
      // ArcRadar cannot see a sensor, so it never claims one is connected.
      await expect(one).not.toContainText(/connected|healthy|online/i);
    }
    await expect(page.getByText(/never as\s+connected/)).toBeVisible();
  });

  test("assets link to the alerts that mention them", async ({ page }) => {
    await page.goto("/telemetry");
    const assets = page.getByRole("region", { name: "Assets" });
    await expect(assets.getByText("DEMO-WIN10-01")).toBeVisible();
    await expect(assets.getByRole("cell", { name: "192.0.2.21", exact: true })).toBeVisible();
    await expect(assets.getByText("Demo data").filter({ visible: true }).first()).toBeVisible();

    await assets.getByRole("link", { name: /DEMO-WIN10-01/ }).click();
    await expect(page).toHaveURL(/\/alerts\?q=DEMO-WIN10-01$/);
    await expect(rows(page).first()).toBeVisible();
    for (const row of await rows(page).all()) await expect(row).toContainText("DEMO-WIN10-01");
  });

  test("events filter, sort and page through the address", async ({ page }) => {
    await page.goto("/telemetry");
    const events = page.getByRole("region", { name: "Events", exact: true });
    await expect(events.locator("tbody tr").first()).toBeVisible();
    await expect(page.getByText(/^\d+ events$/)).toBeVisible();

    await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("demo-edr");
    await expect(page).toHaveURL(/source=demo-edr/);
    for (const row of await events.locator("tbody tr").all())
      await expect(row).toContainText("demo-edr");
    await expect(page.getByText(/events match$/)).toBeVisible();

    await page.getByRole("combobox", { name: "Severity", exact: true }).selectOption("critical");
    await expect(page).toHaveURL(/severity=critical/);
    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await expect(page).toHaveURL(/\/telemetry(#events)?$/);

    await page
      .getByRole("columnheader", { name: /Happened/ })
      .getByRole("link")
      .click();
    await expect(page).toHaveURL(/sort=occurred_at&order=asc/);
    await page.reload();
    await expect(page.getByRole("columnheader", { name: /Happened/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );

    await page.goto("/telemetry?page=999");
    await expect(page.getByRole("heading", { name: "That page is past the end" })).toBeVisible();
    await page.goto("/telemetry?severity=urgent");
    await expect(page.getByText("Some options in the address were not valid")).toBeVisible();
  });
});

test.describe("from a sensor to the screen (administrator)", () => {
  test.use({ storageState: STORAGE.admin });
  test.setTimeout(90_000);

  test("a Wazuh alert arrives with an API key and shows up everywhere it should", async ({
    page,
  }) => {
    const created = await page.request.post("/api/api-keys", {
      data: { name: `${marker} key`, scopes: ["ingest:wazuh"], expires_in_days: 1 },
    });
    expect(created.status()).toBe(201);
    const { key, api_key: info } = (await created.json()).data as {
      key: string;
      api_key: { id: string };
    };

    await test.step("the endpoint refuses anyone without a valid key", async () => {
      expect((await ingest(null, wazuhAlerts(marker))).status).toBe(401);
      expect((await ingest(`arc_${"z".repeat(43)}`, wazuhAlerts(marker))).status).toBe(401);
    });

    await test.step("a valid key delivers a batch, and a resend changes nothing", async () => {
      const sent = await ingest(key, wazuhAlerts(marker));
      expect(sent.status).toBe(200);
      const { data } = await sent.json();
      expect(data).toMatchObject({
        received: 3,
        events_created: 3,
        alerts_created: 2,
        assets_created: 1,
        duplicates: 0,
      });
      const again = await (await ingest(key, wazuhAlerts(marker))).json();
      expect(again.data).toMatchObject({ events_created: 0, alerts_created: 0, duplicates: 3 });
    });

    await test.step("the Telemetry page shows Wazuh as receiving, with the machine and the events", async () => {
      await page.goto("/telemetry");
      const wazuh = card(page, "wazuh", "receiving");
      await expect(wazuh).toBeVisible();
      await expect(wazuh).toContainText("Receiving");
      await expect(wazuh).toContainText("External provider");
      await expect(wazuh).toContainText(/Last received (just now|\d+ minutes? ago)/);
      await expect(wazuh).not.toContainText("Demo data");

      const assets = page.getByRole("region", { name: "Assets" });
      await expect(assets.getByText(`${marker}-WIN10`)).toBeVisible();
      await expect(assets.getByRole("cell", { name: "192.168.56.170", exact: true })).toBeVisible();

      await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("wazuh");
      await expect(page).toHaveURL(/source=wazuh/);
      const events = page.getByRole("region", { name: "Events", exact: true });
      await expect(events.getByText(`${marker} outbound connection`)).toBeVisible();
      await expect(events.getByText(`${marker} routine logon`)).toBeVisible();
      await expect(
        events.getByText("External provider").filter({ visible: true }).first(),
      ).toBeVisible();
      // Only the alerts of level 7 and up raised an alert, and say so.
      await expect(
        events.getByRole("link", { name: `${marker} outbound connection` }),
      ).toBeVisible();
      await expect(events.getByRole("link", { name: `${marker} routine logon` })).toHaveCount(0);
      await expect(
        events.locator("tr", { hasText: `${marker} outbound connection` }),
      ).toContainText("raised an alert");
    });

    await test.step("the alert page shows the sensor, the machine, the techniques and the raw event", async () => {
      await page
        .getByRole("region", { name: "Events", exact: true })
        .getByRole("link", { name: `${marker} multiple logon failures` })
        .click();
      await expect(page).toHaveURL(/\/alerts\/[0-9a-f-]{36}$/);
      await expect(page.getByTestId("alert-title")).toHaveText(`${marker} multiple logon failures`);
      await expect(page.getByText("External provider").first()).toBeVisible();
      await expect(
        page.getByText(/Delivered by wazuh: telemetry sent to ArcRadar's ingest endpoint/),
      ).toBeVisible();
      await expect(page.getByText("This is demo data")).toHaveCount(0);
      await expect(page.getByTestId("alert-status")).toHaveText("New");

      const asset = page.getByTestId("alert-asset");
      await expect(asset).toContainText(`${marker}-WIN10`);
      await expect(asset).toContainText("192.168.56.170");
      await expect(asset).toContainText("Windows");

      // The address the logons came from is the alert's indicator, with no verdict of its own.
      await expect(page.getByRole("link", { name: "198.51.100.180" })).toBeVisible();
      await expect(page.getByText("Unknown").first()).toBeVisible();

      // A technique the workspace knows links to its page; one it does not is plain text.
      const techniques = page.getByRole("list", { name: "ATT&CK techniques" });
      await expect(techniques.getByRole("link", { name: "T1110" })).toHaveAttribute(
        "href",
        "/mitre/T1110",
      );
      await expect(techniques.getByText("T1059.001")).toBeVisible();
      await expect(techniques.getByRole("link", { name: "T1059.001" })).toHaveCount(0);

      await page.getByText("Raw event data").click();
      await expect(page.getByText(`${marker} raw log line`)).toBeVisible();

      await techniques.getByRole("link", { name: "T1110" }).click();
      await expect(page).toHaveURL(/\/mitre\/T1110$/);
    });

    await test.step("it is worked like any other alert, and found by its machine's name", async () => {
      await page.goto(`/alerts?q=${encodeURIComponent(`${marker}-WIN10`)}`);
      await expect(rows(page)).toHaveCount(2);
      await expect(rows(page).first()).toContainText(`wazuh · ${marker}-WIN10`);
      await expect(rows(page).first()).toContainText("External provider");
      await page.getByRole("combobox", { name: "Source", exact: true }).selectOption("wazuh");
      await expect(rows(page)).toHaveCount(2);

      await rows(page).first().getByRole("link").first().click();
      await page.getByTestId("alert-actions").getByRole("button", { name: "Acknowledge" }).click();
      await expect(page.getByTestId("alert-status")).toHaveText("Acknowledged");
    });

    await test.step("revoking the key stops it at once", async () => {
      const revoked = await page.request.delete(`/api/api-keys/${info.id}`);
      expect(revoked.status()).toBe(200);
      expect((await ingest(key, wazuhAlerts(marker))).status).toBe(401);
    });
  });

  test("a demo feed is never shown as receiving, whatever its rows say", async ({ page }) => {
    await page.goto("/telemetry");
    await expect(card(page, "demo-edr", "receiving")).toHaveCount(0);
    await expect(
      page.locator('[data-testid="source-card"][data-status="demo"]').first(),
    ).toBeVisible();
  });
});

test.describe("who may issue an ingest key", () => {
  test.use({ storageState: STORAGE.analyst });

  test("an analyst cannot, and gets a plain reason", async ({ page }) => {
    const denied = await page.request.post("/api/api-keys", {
      data: { name: `${marker} analyst`, scopes: ["ingest:wazuh"], expires_in_days: 1 },
    });
    expect(denied.status()).toBe(403);
    const body = await denied.json();
    expect(body.success).toBe(false);
    expect(JSON.stringify(body)).not.toMatch(/arc_[A-Za-z0-9_-]{43}/);
  });
});
