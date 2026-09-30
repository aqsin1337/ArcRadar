import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";
import {
  addAlertLinkSchema,
  addIndicatorLinkSchema,
  createInvestigationSchema,
  evidenceSchema,
  investigationListQuerySchema,
  noteSchema,
  updateInvestigationSchema,
} from "@/lib/investigations/schema";
import { buildInvestigationTimeline } from "@/lib/investigations/timeline";
import type {
  InvestigationEvidence,
  InvestigationNote,
  LinkedAlert,
  LinkedIndicator,
} from "@/lib/investigations/types";
import { hasActiveInvestigationFilters, investigationListHref } from "@/lib/investigations/url";
import type { Alert, Investigation } from "@/types/domain";

const repo = vi.hoisted(() => ({
  deleteAlertLink: vi.fn(),
  deleteChecklistItemRow: vi.fn(),
  deleteEvidenceRow: vi.fn(),
  deleteIndicatorLink: vi.fn(),
  deleteInvestigationRow: vi.fn(),
  deleteNoteRow: vi.fn(),
  findChecklistItems: vi.fn(),
  findInvestigationDetail: vi.fn(),
  findInvestigationRow: vi.fn(),
  findInvestigationStats: vi.fn(),
  findInvestigations: vi.fn(),
  findLinkLabel: vi.fn(),
  findNote: vi.fn(),
  insertAlertLinks: vi.fn(),
  insertChecklistItem: vi.fn(),
  insertChecklistItems: vi.fn(),
  insertEvidence: vi.fn(),
  insertIndicatorLinks: vi.fn(),
  insertInvestigation: vi.fn(),
  insertNote: vi.fn(),
  insertSystemNote: vi.fn(),
  replaceInvestigationTags: vi.fn(),
  updateChecklistItemRow: vi.fn(),
  updateInvestigationRow: vi.fn(),
  updateNoteRow: vi.fn(),
}));
const alerts = vi.hoisted(() => ({ findAlertRow: vi.fn(), updateAlertRow: vi.fn() }));
const team = vi.hoisted(() => ({ findMember: vi.fn(), findDisplayNames: vi.fn() }));
const audit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/investigations/repository", () => repo);
vi.mock("@/lib/alerts/repository", () => alerts);
vi.mock("@/lib/team/repository", () => team);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const {
  addChecklistItem,
  addEvidence,
  addNote,
  attachAlert,
  createInvestigation,
  detachIndicator,
  editNote,
  removeChecklistItem,
  removeNote,
  toggleChecklistItem,
  updateInvestigation,
} = await import("@/lib/investigations/service");

const ID = "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d";
const ALERT_ID = "5c1f7d20-8d4b-4a53-8a1e-2b7f9c0d1e3f";
const INDICATOR_ID = "9a3c2e10-1b7d-4e6f-a0c4-5d8e7f6a4b3c";
const ANALYST = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const OTHER = "7e2b1c90-4a6d-4f3e-b8a5-0c9d8e7f6a5b";
const NOW = new Date("2026-09-27T10:00:00.000Z");
const request = { headers: new Headers() };

const auth = (role: "admin" | "soc_l2" = "soc_l2", supabase = {} as AuthClient): AuthContext => ({
  supabase,
  user: { id: ANALYST, email: "analyst@arcradar.test" },
  profile: { display_name: "Analyst", role },
  permissions: permissionsForRole(role),
});

const investigation = (overrides: Partial<Investigation> = {}): Investigation =>
  ({
    id: ID,
    title: "Harbor Lights",
    description: null,
    status: "open",
    priority: "medium",
    analyst_id: ANALYST,
    origin: "local",
    closed_at: null,
    created_by: ANALYST,
    created_at: "2026-09-27T08:00:00.000Z",
    updated_at: "2026-09-27T08:00:00.000Z",
    ...overrides,
  }) as Investigation;

const alertRow = (overrides: Partial<Alert> = {}): Alert =>
  ({
    id: ALERT_ID,
    title: "Beacon",
    status: "new",
    acknowledged_at: null,
    resolved_at: null,
    assigned_to: null,
    ...overrides,
  }) as Alert;

/** A Supabase client that answers `from(t).select("id").in("id", ids)` with `existing` of the ids. */
const supabaseWith = (existing: (ids: string[]) => string[]) =>
  ({
    from: () => ({
      select: () => ({
        in: async (_column: string, ids: string[]) => ({
          data: existing(ids).map((id) => ({ id })),
          error: null,
        }),
      }),
    }),
  }) as unknown as AuthClient;

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected the call to fail");
}

describe("investigation schemas", () => {
  it("parses the list query with defaults, blanks as not set and the analyst filter", () => {
    expect(investigationListQuerySchema.parse({ q: "", status: "" })).toMatchObject({
      q: undefined,
      status: undefined,
      sort: "updated_at",
      order: "desc",
    });
    expect(investigationListQuerySchema.parse({ analyst: "me" }).analyst).toBe("me");
    expect(investigationListQuerySchema.safeParse({ analyst: "everyone" }).success).toBe(false);
    expect(investigationListQuerySchema.safeParse({ status: "archived" }).success).toBe(false);
  });

  it("opens only local, open investigations: no status, origin or owner from the client", () => {
    const parsed = createInvestigationSchema.parse({
      title: "  Harbor Lights ",
      description: "",
      tags: ["c2", "C2", "phishing"],
      indicator_ids: [INDICATOR_ID, INDICATOR_ID],
    });
    expect(parsed).toMatchObject({
      title: "Harbor Lights",
      description: null,
      tags: ["c2", "phishing"], // duplicates ignoring case are dropped
      indicator_ids: [INDICATOR_ID], // and so are duplicate ids
    });
    for (const extra of [{ status: "closed" }, { origin: "external" }, { created_by: ANALYST }]) {
      expect(createInvestigationSchema.safeParse({ title: "x", ...extra }).success).toBe(false);
    }
    expect(createInvestigationSchema.safeParse({ title: " " }).success).toBe(false);
  });

  it("limits how much can be attached at once", () => {
    const many = (count: number) =>
      Array.from(
        { length: count },
        (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
      );
    expect(
      createInvestigationSchema.safeParse({ title: "x", indicator_ids: many(50) }).success,
    ).toBe(true);
    expect(
      createInvestigationSchema.safeParse({ title: "x", indicator_ids: many(51) }).success,
    ).toBe(false);
    expect(createInvestigationSchema.safeParse({ title: "x", alert_ids: many(21) }).success).toBe(
      false,
    );
  });

  it("needs at least one field to update, and lets the analyst be me, a person or nobody", () => {
    expect(updateInvestigationSchema.safeParse({}).success).toBe(false);
    for (const analyst_id of ["me", ANALYST, null]) {
      expect(updateInvestigationSchema.safeParse({ analyst_id }).success).toBe(true);
    }
    expect(updateInvestigationSchema.safeParse({ status: "closed", origin: "demo" }).success).toBe(
      false,
    );
  });

  it("validates link, note and evidence bodies strictly", () => {
    expect(addIndicatorLinkSchema.safeParse({ indicator_id: "nope" }).success).toBe(false);
    expect(addAlertLinkSchema.safeParse({ alert_id: ALERT_ID, extra: 1 }).success).toBe(false);
    expect(noteSchema.parse({ body: "  Confirmed in the proxy logs.  " })).toEqual({
      body: "Confirmed in the proxy logs.",
    });
    expect(noteSchema.safeParse({ body: "   " }).success).toBe(false);
    expect(noteSchema.safeParse({ body: "x", kind: "system" }).success).toBe(false);
    expect(
      evidenceSchema.parse({ title: "PCAP", location: "ticket #4711", description: "" }),
    ).toEqual({
      title: "PCAP",
      location: "ticket #4711",
      description: null,
    });
    expect(evidenceSchema.safeParse({ title: "PCAP", location: " " }).success).toBe(false);
  });
});

describe("investigation list address", () => {
  it("leaves defaults out and keeps filters, sort and page", () => {
    expect(investigationListHref({})).toBe("/investigations");
    expect(investigationListHref({ sort: "updated_at", order: "desc", page: 1 })).toBe(
      "/investigations",
    );
    expect(investigationListHref({ q: "harbor", status: "open" }, { analyst: "me", page: 2 })).toBe(
      "/investigations?q=harbor&status=open&analyst=me&page=2",
    );
    expect(hasActiveInvestigationFilters({ page: 4, sort: "priority" })).toBe(false);
    expect(hasActiveInvestigationFilters({ tag: "c2" })).toBe(true);
  });
});

describe("buildInvestigationTimeline", () => {
  const note = (overrides: Partial<InvestigationNote>): InvestigationNote => ({
    id: "n",
    kind: "note",
    body: "text",
    author_id: ANALYST,
    author_name: "Analyst",
    created_at: "2026-09-27T09:00:00.000Z",
    updated_at: "2026-09-27T09:00:00.000Z",
    ...overrides,
  });

  it("merges everything that happened, newest first, and tells notes from status history", () => {
    const evidence: InvestigationEvidence[] = [
      {
        id: "e",
        title: "PCAP",
        location: "ticket #4711",
        description: null,
        added_by_name: "Analyst",
        created_at: "2026-09-27T11:00:00.000Z",
      },
    ];
    const indicators = [
      {
        id: "i",
        value: "203.0.113.9",
        added_at: "2026-09-27T08:30:00.000Z",
        added_by_name: "Analyst",
      },
    ] as LinkedIndicator[];
    const alertsAttached = [
      { id: "a", title: "Beacon", added_at: "2026-09-27T08:45:00.000Z", added_by_name: null },
    ] as LinkedAlert[];

    const entries = buildInvestigationTimeline({
      created_at: "2026-09-27T08:00:00.000Z",
      created_by_name: "Analyst",
      notes: [
        note({ id: "n1", body: "Confirmed in the proxy logs." }),
        note({
          id: "n2",
          kind: "system",
          body: "Status changed from Open to Investigating.",
          created_at: "2026-09-27T10:00:00.000Z",
        }),
      ],
      evidence,
      indicators,
      alerts: alertsAttached,
    });

    expect(entries.map((entry) => entry.kind)).toEqual([
      "evidence",
      "system",
      "note",
      "alert",
      "indicator",
      "opened",
    ]);
    expect(entries[1]).toMatchObject({
      title: "Status changed from Open to Investigating.",
      detail: null,
    });
    expect(entries[2]).toMatchObject({
      title: "Note added",
      detail: "Confirmed in the proxy logs.",
    });
    expect(entries[3]).toMatchObject({ title: "Alert attached", detail: "Beacon" });
    expect(entries.at(-1)).toMatchObject({ title: "Investigation opened", actor: "Analyst" });
  });

  it("has just the opening entry for an empty investigation", () => {
    const entries = buildInvestigationTimeline({
      created_at: "2026-09-27T08:00:00.000Z",
      created_by_name: null,
      notes: [],
      evidence: [],
      indicators: [],
      alerts: [],
    });
    expect(entries).toHaveLength(1);
  });
});

describe("createInvestigation", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    team.findMember.mockResolvedValue({ id: ANALYST });
    repo.insertInvestigation.mockResolvedValue(investigation());
    repo.findInvestigationDetail.mockResolvedValue({ ...investigation() });
  });

  it("opens it for the caller by default, attaches what was given and audits the counts", async () => {
    const supabase = supabaseWith((ids) => ids);
    alerts.findAlertRow.mockResolvedValue(alertRow());
    alerts.updateAlertRow.mockResolvedValue(alertRow({ status: "investigating" }));

    await createInvestigation(
      auth("soc_l2", supabase),
      {
        title: "Harbor Lights",
        indicator_ids: [INDICATOR_ID],
        alert_ids: [ALERT_ID],
        tags: ["c2"],
      },
      request,
    );

    expect(repo.insertInvestigation).toHaveBeenCalledWith(supabase, {
      title: "Harbor Lights",
      description: undefined,
      priority: undefined,
      analyst_id: ANALYST,
    });
    expect(repo.replaceInvestigationTags).toHaveBeenCalledWith(supabase, ID, ["c2"]);
    expect(repo.insertIndicatorLinks).toHaveBeenCalledWith(supabase, ID, [INDICATOR_ID]);
    expect(repo.insertAlertLinks).toHaveBeenCalledWith(supabase, ID, [ALERT_ID]);

    const created = audit.mock.calls
      .map(([entry]) => entry)
      .find((entry) => entry.action === "investigation.created");
    expect(created.metadata).toEqual({
      title: "Harbor Lights",
      priority: "medium",
      indicators: 1,
      alerts: 1,
    });
  });

  it("moves an attached new alert to investigating, through the same lifecycle rules", async () => {
    alerts.findAlertRow.mockResolvedValue(alertRow());
    alerts.updateAlertRow.mockResolvedValue(alertRow({ status: "investigating" }));

    await createInvestigation(
      auth(
        "soc_l2",
        supabaseWith((ids) => ids),
      ),
      { title: "Harbor Lights", alert_ids: [ALERT_ID] },
      request,
    );

    const [, alertId, patch, expected] = alerts.updateAlertRow.mock.calls[0];
    expect(alertId).toBe(ALERT_ID);
    expect(patch).toMatchObject({
      status: "investigating",
      resolved_at: null,
      assigned_to: ANALYST,
    });
    expect(expected).toBe("new");
    const change = audit.mock.calls
      .map(([entry]) => entry)
      .find((entry) => entry.action === "alert.status_changed");
    expect(change.metadata).toMatchObject({
      from: "new",
      to: "investigating",
      reason: "attached to an investigation",
    });
  });

  it("leaves an alert that is already closed, or that changed meanwhile, alone", async () => {
    alerts.findAlertRow.mockResolvedValueOnce(alertRow({ status: "resolved" }));
    await createInvestigation(
      auth(
        "soc_l2",
        supabaseWith((ids) => ids),
      ),
      { title: "x", alert_ids: [ALERT_ID] },
      request,
    );
    expect(alerts.updateAlertRow).not.toHaveBeenCalled();

    alerts.findAlertRow.mockResolvedValueOnce(alertRow());
    alerts.updateAlertRow.mockResolvedValueOnce(null); // somebody else got there first
    await createInvestigation(
      auth(
        "soc_l2",
        supabaseWith((ids) => ids),
      ),
      { title: "x", alert_ids: [ALERT_ID] },
      request,
    );
    expect(
      audit.mock.calls.filter(([entry]) => entry.action === "alert.status_changed"),
    ).toHaveLength(0);
  });

  it("fails before creating anything when an attached record does not exist (422)", async () => {
    const error = await failureOf(
      createInvestigation(
        auth(
          "soc_l2",
          supabaseWith(() => []),
        ),
        { title: "x", indicator_ids: [INDICATOR_ID] },
        request,
      ),
    );
    expect(error).toMatchObject({ status: 422 });
    expect(repo.insertInvestigation).not.toHaveBeenCalled();
  });

  it("only assigns people who may work investigations (422), and lets it stay unassigned", async () => {
    team.findMember.mockResolvedValue(null);
    expect(
      await failureOf(createInvestigation(auth(), { title: "x", analyst_id: OTHER }, request)),
    ).toMatchObject({ status: 422 });
    expect(repo.insertInvestigation).not.toHaveBeenCalled();

    await createInvestigation(auth(), { title: "x", analyst_id: null }, request);
    expect(repo.insertInvestigation.mock.calls[0][1]).toMatchObject({ analyst_id: null });
  });
});

describe("updateInvestigation", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    team.findMember.mockResolvedValue({ id: OTHER });
    team.findDisplayNames.mockResolvedValue(new Map([[OTHER, "Second Analyst"]]));
    repo.findInvestigationRow.mockResolvedValue(investigation());
    repo.findInvestigationDetail.mockResolvedValue(investigation());
    repo.updateInvestigationRow.mockImplementation(async (_s, _id, patch) => investigation(patch));
  });

  it("stamps closed_at when it is closed, records the history and audits the change", async () => {
    await updateInvestigation(auth(), ID, { status: "closed" }, request, () => NOW);

    expect(repo.updateInvestigationRow).toHaveBeenCalledWith(expect.anything(), ID, {
      status: "closed",
      closed_at: NOW.toISOString(),
    });
    expect(repo.insertSystemNote).toHaveBeenCalledWith(
      ID,
      ANALYST,
      "Status changed from Open to Closed.",
    );
    const entry = audit.mock.calls[0][0];
    expect(entry).toMatchObject({ action: "investigation.updated", entityId: ID });
    expect(entry.metadata).toMatchObject({
      fields: ["status"],
      status_from: "open",
      status_to: "closed",
    });
  });

  it("clears closed_at when a closed investigation is reopened", async () => {
    repo.findInvestigationRow.mockResolvedValue(
      investigation({ status: "closed", closed_at: NOW.toISOString() }),
    );
    await updateInvestigation(auth(), ID, { status: "investigating" }, request);
    expect(repo.updateInvestigationRow.mock.calls[0][2]).toEqual({
      status: "investigating",
      closed_at: null,
    });
  });

  it("records who it was assigned to, and who took it away", async () => {
    await updateInvestigation(auth(), ID, { analyst_id: OTHER }, request);
    expect(repo.insertSystemNote).toHaveBeenLastCalledWith(
      ID,
      ANALYST,
      "Assigned to Second Analyst.",
    );

    await updateInvestigation(auth(), ID, { analyst_id: null }, request);
    expect(repo.insertSystemNote).toHaveBeenLastCalledWith(ID, ANALYST, "Unassigned.");
  });

  it("does not report a change that changes nothing", async () => {
    await updateInvestigation(
      auth(),
      ID,
      { title: "Harbor Lights", priority: "medium", status: "open" },
      request,
    );
    expect(repo.updateInvestigationRow.mock.calls[0][2]).toEqual({});
    expect(repo.insertSystemNote).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("keeps the change when writing the history fails", async () => {
    repo.insertSystemNote.mockRejectedValue(new Error("history table unavailable"));
    await expect(
      updateInvestigation(auth(), ID, { priority: "high" }, request),
    ).resolves.toBeDefined();
    expect(audit.mock.calls[0][0].action).toBe("investigation.updated");
  });

  it("refuses an analyst who may not work investigations (422) without changing anything", async () => {
    team.findMember.mockResolvedValue(null);
    const error = await failureOf(updateInvestigation(auth(), ID, { analyst_id: OTHER }, request));
    expect(error).toMatchObject({ status: 422 });
    expect(repo.updateInvestigationRow).not.toHaveBeenCalled();
  });

  it("answers 404 for a malformed or unknown id", async () => {
    expect(
      await failureOf(updateInvestigation(auth(), "nope", { title: "x" }, request)),
    ).toMatchObject({ status: 404 });
    repo.findInvestigationRow.mockResolvedValue(null);
    expect(await failureOf(updateInvestigation(auth(), ID, { title: "x" }, request))).toMatchObject(
      { status: 404 },
    );
  });
});

describe("links, notes and evidence", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findInvestigationRow.mockResolvedValue(investigation());
    repo.findInvestigationDetail.mockResolvedValue(investigation());
    repo.updateInvestigationRow.mockResolvedValue(investigation());
    repo.findLinkLabel.mockResolvedValue("203.0.113.9");
  });

  it("attaching an alert starts work on it and audits the link", async () => {
    alerts.findAlertRow.mockResolvedValue(
      alertRow({ status: "acknowledged", acknowledged_at: NOW.toISOString(), assigned_to: OTHER }),
    );
    alerts.updateAlertRow.mockResolvedValue(alertRow({ status: "investigating" }));
    await attachAlert(auth(), ID, ALERT_ID, request);

    expect(repo.insertAlertLinks).toHaveBeenCalledWith(expect.anything(), ID, [ALERT_ID]);
    expect(alerts.updateAlertRow.mock.calls[0][3]).toBe("acknowledged");
    expect(audit.mock.calls.map(([entry]) => entry.action)).toEqual([
      "alert.status_changed",
      "investigation.link_added",
    ]);
  });

  it("detaching something that is not attached is 404, and writes no audit entry", async () => {
    repo.deleteIndicatorLink.mockResolvedValue(false);
    const error = await failureOf(detachIndicator(auth(), ID, INDICATOR_ID, request));
    expect(error).toMatchObject({ status: 404 });
    expect(audit).not.toHaveBeenCalled();
  });

  it("adds a note and evidence, and audits each", async () => {
    repo.insertNote.mockResolvedValue({ id: "note-1" });
    repo.insertEvidence.mockResolvedValue({ id: "evidence-1" });
    await addNote(auth(), ID, { body: "Confirmed." }, request);
    await addEvidence(auth(), ID, { title: "PCAP", location: "ticket #4711" }, request);

    expect(audit.mock.calls.map(([entry]) => entry.action)).toEqual([
      "investigation.note_added",
      "investigation.evidence_added",
    ]);
    expect(audit.mock.calls[1][0].metadata).toMatchObject({ evidence: "PCAP" });
  });

  it("lets only the author edit a note, and nobody edit the status history", async () => {
    repo.findNote.mockResolvedValue({ id: "n", author_id: OTHER, kind: "note" });
    expect(
      await failureOf(editNote(auth("admin"), ID, ALERT_ID, { body: "x" }, request)),
    ).toMatchObject({ status: 403 });

    repo.findNote.mockResolvedValue({ id: "n", author_id: ANALYST, kind: "system" });
    const error = await failureOf(editNote(auth(), ID, ALERT_ID, { body: "x" }, request));
    expect(error).toMatchObject({ status: 403 });
    expect(error.message).toMatch(/status history/i);
    expect(repo.updateNoteRow).not.toHaveBeenCalled();
  });

  it("lets an administrator remove somebody else's note, but not an analyst, and never the history", async () => {
    repo.findNote.mockResolvedValue({ id: "n", author_id: OTHER, kind: "note" });
    repo.deleteNoteRow.mockResolvedValue(true);

    expect(await failureOf(removeNote(auth("soc_l2"), ID, ALERT_ID, request))).toMatchObject({
      status: 403,
    });
    await expect(removeNote(auth("admin"), ID, ALERT_ID, request)).resolves.toBeDefined();
    expect(audit.mock.calls.at(-1)?.[0].action).toBe("investigation.note_deleted");

    repo.findNote.mockResolvedValue({ id: "n", author_id: OTHER, kind: "system" });
    expect(await failureOf(removeNote(auth("admin"), ID, ALERT_ID, request))).toMatchObject({
      status: 403,
    });
  });
});

describe("checklist", () => {
  const item = {
    id: "c1c1c1c1-0000-4000-8000-000000000001",
    text: "Pull DNS logs",
    done: false,
    source: "analyst" as const,
    created_by_name: "Analyst",
    created_at: NOW.toISOString(),
    done_by_name: null,
    done_at: null,
  };

  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findInvestigationRow.mockResolvedValue(investigation());
    repo.updateInvestigationRow.mockResolvedValue(investigation());
    repo.findChecklistItems.mockResolvedValue([item]);
  });

  it("adds an item as the analyst and audits it", async () => {
    const items = await addChecklistItem(auth("soc_l2"), ID, { text: item.text }, request);
    expect(items).toEqual([item]);
    expect(repo.insertChecklistItem).toHaveBeenCalledWith(
      expect.anything(),
      ID,
      item.text,
      "analyst",
    );
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({
      action: "investigation.checklist_item_added",
    });
  });

  it("toggling done records who and when; unchecking clears it", async () => {
    repo.updateChecklistItemRow.mockResolvedValue(true);
    await toggleChecklistItem(auth("soc_l2"), ID, item.id, true, request, () => NOW);
    expect(repo.updateChecklistItemRow).toHaveBeenCalledWith(expect.anything(), item.id, {
      done: true,
      done_by: ANALYST,
      done_at: NOW.toISOString(),
    });

    await toggleChecklistItem(auth("soc_l2"), ID, item.id, false, request, () => NOW);
    expect(repo.updateChecklistItemRow).toHaveBeenLastCalledWith(expect.anything(), item.id, {
      done: false,
      done_by: null,
      done_at: null,
    });
  });

  it("404s toggling or removing an item that does not exist", async () => {
    repo.updateChecklistItemRow.mockResolvedValue(false);
    expect(
      await failureOf(toggleChecklistItem(auth("soc_l2"), ID, item.id, true, request)),
    ).toMatchObject({ status: 404 });

    repo.deleteChecklistItemRow.mockResolvedValue(false);
    expect(
      await failureOf(removeChecklistItem(auth("soc_l2"), ID, item.id, request)),
    ).toMatchObject({ status: 404 });
  });

  it("removing an item audits it", async () => {
    repo.deleteChecklistItemRow.mockResolvedValue(true);
    await removeChecklistItem(auth("soc_l2"), ID, item.id, request);
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({
      action: "investigation.checklist_item_removed",
    });
  });
});
