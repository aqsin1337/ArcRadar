import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import { ALERT_STATUSES } from "@/lib/alerts/constants";
import { alertListQuerySchema, createAlertSchema, updateAlertSchema } from "@/lib/alerts/schema";
import { buildAlertTimeline } from "@/lib/alerts/timeline";
import { alertListHref, hasActiveAlertFilters } from "@/lib/alerts/url";
import {
  ALERT_TRANSITIONS,
  buildStatusPatch,
  canTransition,
  isClosed,
} from "@/lib/alerts/workflow";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { Alert, AlertStatus } from "@/types/domain";

const repo = vi.hoisted(() => ({
  findAlerts: vi.fn(),
  findAlertDetail: vi.fn(),
  findAlertRow: vi.fn(),
  findAlertStats: vi.fn(),
  findAlertSources: vi.fn(),
  insertAlert: vi.fn(),
  updateAlertRow: vi.fn(),
  deleteAlertRow: vi.fn(),
}));
const team = vi.hoisted(() => ({ findMember: vi.fn() }));
const audit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/alerts/repository", () => repo);
vi.mock("@/lib/team/repository", () => team);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const { createAlert, deleteAlert, getAlert, updateAlert } = await import("@/lib/alerts/service");

const ID = "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d";
const ANALYST = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const NOW = new Date("2026-09-27T10:00:00.000Z");
const request = { headers: new Headers() };

const auth = (): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: ANALYST, email: "analyst@arcradar.test" },
  profile: { display_name: "Analyst", role: "analyst" },
  permissions: permissionsForRole("analyst"),
});

const alert = (overrides: Partial<Alert> = {}): Alert =>
  ({
    id: ID,
    title: "Beacon to 203.0.113.9",
    description: null,
    severity: "high",
    status: "new",
    source: "wazuh",
    origin: "demo",
    indicator_id: null,
    event_id: null,
    assigned_to: null,
    acknowledged_at: null,
    resolved_at: null,
    created_by: null,
    created_at: "2026-09-27T08:00:00.000Z",
    updated_at: "2026-09-27T08:00:00.000Z",
    ...overrides,
  }) as Alert;

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected the call to fail");
}

describe("alert lifecycle", () => {
  it("lets an alert move only along the documented transitions", () => {
    const allowed = Object.entries(ALERT_TRANSITIONS).flatMap(([from, targets]) =>
      targets.map((to) => `${from}>${to}`),
    );
    expect(allowed.sort()).toEqual(
      [
        "new>acknowledged",
        "new>investigating",
        "new>resolved",
        "new>false_positive",
        "acknowledged>investigating",
        "acknowledged>resolved",
        "acknowledged>false_positive",
        "investigating>resolved",
        "investigating>false_positive",
        "resolved>investigating",
        "false_positive>investigating",
      ].sort(),
    );
  });

  it("never goes back to new, never stays where it is, and reopens only into investigating", () => {
    for (const from of ALERT_STATUSES) {
      expect(canTransition(from, "new")).toBe(false);
      expect(canTransition(from, from)).toBe(false);
    }
    expect(canTransition("resolved", "acknowledged")).toBe(false);
    expect(canTransition("resolved", "false_positive")).toBe(false);
    expect(canTransition("false_positive", "investigating")).toBe(true);
  });

  it("knows which statuses are closed", () => {
    const closed = ALERT_STATUSES.filter(isClosed);
    expect(closed).toEqual(["resolved", "false_positive"]);
  });
});

describe("buildStatusPatch", () => {
  const fresh = {
    status: "new",
    acknowledged_at: null,
    resolved_at: null,
    assigned_to: null,
  } as const;

  it("stamps acknowledged_at when the alert first leaves new, and takes an unassigned alert", () => {
    expect(buildStatusPatch(fresh, "acknowledged", NOW, ANALYST)).toEqual({
      status: "acknowledged",
      acknowledged_at: NOW.toISOString(),
      resolved_at: null,
      assigned_to: ANALYST,
    });
  });

  it("does not take an alert that somebody already owns", () => {
    const patch = buildStatusPatch(
      { ...fresh, assigned_to: "someone-else" },
      "investigating",
      NOW,
      ANALYST,
    );
    expect(patch).not.toHaveProperty("assigned_to");
  });

  it("sets resolved_at exactly when the alert is closed, and clears it on reopening", () => {
    const acknowledged = "2026-09-27T09:00:00.000Z";
    const working = {
      status: "investigating",
      acknowledged_at: acknowledged,
      resolved_at: null,
      assigned_to: ANALYST,
    } as const;
    for (const closed of ["resolved", "false_positive"] as const) {
      const patch = buildStatusPatch(working, closed, NOW, ANALYST);
      expect(patch.resolved_at).toBe(NOW.toISOString());
      expect(patch.acknowledged_at).toBe(acknowledged); // kept
    }
    const reopened = buildStatusPatch(
      { ...working, status: "resolved", resolved_at: NOW.toISOString() },
      "investigating",
      NOW,
      ANALYST,
    );
    expect(reopened.resolved_at).toBeNull();
    expect(reopened.acknowledged_at).toBe(acknowledged);
  });

  it("satisfies the database rule: resolved_at is set for exactly the closed statuses", () => {
    for (const next of ALERT_STATUSES as readonly AlertStatus[]) {
      const patch = buildStatusPatch(fresh, next, NOW, ANALYST);
      expect(patch.resolved_at !== null).toBe(isClosed(next));
    }
  });
});

describe("alert schemas", () => {
  it("parses the list query with defaults and treats blanks as not set", () => {
    const query = alertListQuerySchema.parse({ q: "", status: "", severity: "high" });
    expect(query).toMatchObject({
      q: undefined,
      status: undefined,
      severity: "high",
      sort: "created_at",
      order: "desc",
      page: 1,
    });
  });

  it("accepts me, none or a user id as the assignee filter, and nothing else", () => {
    expect(alertListQuerySchema.parse({ assignee: "me" }).assignee).toBe("me");
    expect(alertListQuerySchema.parse({ assignee: "none" }).assignee).toBe("none");
    expect(alertListQuerySchema.parse({ assignee: ANALYST }).assignee).toBe(ANALYST);
    expect(alertListQuerySchema.safeParse({ assignee: "everyone" }).success).toBe(false);
  });

  it("hides duplicates by default; only the literal 'show' reveals them", () => {
    expect(alertListQuerySchema.parse({}).duplicates).toBeUndefined();
    expect(alertListQuerySchema.parse({ duplicates: "" }).duplicates).toBeUndefined();
    expect(alertListQuerySchema.parse({ duplicates: "show" }).duplicates).toBe("show");
    expect(alertListQuerySchema.safeParse({ duplicates: "all" }).success).toBe(false);
  });

  it("creates only manual alerts: strict body, no origin, source or owner from the client", () => {
    expect(createAlertSchema.parse({ title: "  Odd login  ", description: "" })).toEqual({
      title: "Odd login",
      description: null,
    });
    for (const extra of [{ origin: "external" }, { source: "wazuh" }, { created_by: ANALYST }]) {
      expect(createAlertSchema.safeParse({ title: "x", ...extra }).success).toBe(false);
    }
    expect(createAlertSchema.safeParse({ title: "   " }).success).toBe(false);
    expect(createAlertSchema.safeParse({ title: "x", severity: "urgent" }).success).toBe(false);
  });

  it("needs a status or an assignee to update, and never accepts other columns", () => {
    expect(updateAlertSchema.safeParse({}).success).toBe(false);
    expect(updateAlertSchema.safeParse({ status: "acknowledged" }).success).toBe(true);
    expect(updateAlertSchema.safeParse({ assigned_to: "me" }).success).toBe(true);
    expect(updateAlertSchema.safeParse({ assigned_to: null }).success).toBe(true);
    expect(updateAlertSchema.safeParse({ status: "new", severity: "low" }).success).toBe(false);
    expect(updateAlertSchema.safeParse({ resolved_at: NOW.toISOString() }).success).toBe(false);
  });
});

describe("alert list address", () => {
  it("leaves defaults out and keeps filters, sort and page", () => {
    expect(alertListHref({})).toBe("/alerts");
    expect(alertListHref({ sort: "created_at", order: "desc", page: 1, q: "" })).toBe("/alerts");
    expect(
      alertListHref(
        { q: "beacon", status: "new", assignee: "none" },
        { sort: "severity", order: "asc", page: 2 },
      ),
    ).toBe("/alerts?q=beacon&status=new&assignee=none&sort=severity&order=asc&page=2");
  });

  it("says whether a filter is active (sorting and paging do not count)", () => {
    expect(hasActiveAlertFilters({ sort: "severity", page: 3 })).toBe(false);
    expect(hasActiveAlertFilters({ source: "wazuh" })).toBe(true);
  });
});

describe("buildAlertTimeline", () => {
  it("lists what is recorded, newest first", () => {
    const entries = buildAlertTimeline({
      created_at: "2026-09-27T08:00:00.000Z",
      acknowledged_at: "2026-09-27T09:00:00.000Z",
      resolved_at: "2026-09-27T11:00:00.000Z",
      status: "false_positive",
      source: "wazuh",
      investigations: [
        {
          id: "i-1",
          title: "Harbor Lights",
          status: "open",
          priority: "high",
          added_at: "2026-09-27T10:00:00.000Z",
        },
      ],
    });
    expect(entries.map((entry) => entry.title)).toEqual([
      "Closed as false positive",
      "Added to an investigation",
      "Acknowledged",
      "Raised",
    ]);
    expect(entries.at(-1)?.detail).toBe("Source: wazuh");
    expect(entries[1].detail).toBe("Harbor Lights");
  });

  it("shows only that an untouched alert was raised", () => {
    const entries = buildAlertTimeline({
      created_at: "2026-09-27T08:00:00.000Z",
      acknowledged_at: null,
      resolved_at: null,
      status: "new",
      source: "manual",
      investigations: [],
    });
    expect(entries).toHaveLength(1);
  });
});

describe("updateAlert", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    team.findMember.mockResolvedValue({ id: ANALYST, display_name: "Analyst", role: "analyst" });
    repo.findAlertRow.mockResolvedValue(alert());
    repo.findAlertDetail.mockResolvedValue({ ...alert(), investigations: [] });
  });

  it("acknowledges a new alert, takes it, and audits both the status change and the assignment", async () => {
    repo.updateAlertRow.mockResolvedValue(
      alert({ status: "acknowledged", assigned_to: ANALYST, acknowledged_at: NOW.toISOString() }),
    );
    await updateAlert(auth(), ID, { status: "acknowledged" }, request, () => NOW);

    expect(repo.updateAlertRow).toHaveBeenCalledWith(
      expect.anything(),
      ID,
      {
        status: "acknowledged",
        acknowledged_at: NOW.toISOString(),
        resolved_at: null,
        assigned_to: ANALYST,
      },
      "new", // the update only applies while the alert is still `new`
    );
    expect(audit.mock.calls.map(([entry]) => entry.action)).toEqual([
      "alert.status_changed",
      "alert.assigned",
    ]);
    expect(audit.mock.calls[0][0].metadata).toEqual({
      title: "Beacon to 203.0.113.9",
      from: "new",
      to: "acknowledged",
    });
  });

  it("refuses a move the lifecycle does not allow (409) and changes nothing", async () => {
    repo.findAlertRow.mockResolvedValue(alert({ status: "resolved" }));
    const error = await failureOf(updateAlert(auth(), ID, { status: "acknowledged" }, request));

    expect(error).toMatchObject({ status: 409, code: "CONFLICT" });
    expect(error.message).toMatch(/resolved.*cannot become acknowledged/i);
    expect(repo.updateAlertRow).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("says so (409) when somebody else changed the alert in the meantime", async () => {
    repo.updateAlertRow.mockResolvedValue(null);
    const error = await failureOf(updateAlert(auth(), ID, { status: "investigating" }, request));
    expect(error).toMatchObject({ status: 409 });
    expect(error.message).toMatch(/changed by someone else/i);
    expect(audit).not.toHaveBeenCalled();
  });

  it("does nothing, and writes no audit entry, when the status is already the one asked for", async () => {
    await updateAlert(auth(), ID, { status: "new" }, request);
    expect(repo.updateAlertRow).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("assigns to `me` as the caller and audits the assignment only", async () => {
    repo.updateAlertRow.mockResolvedValue(alert({ assigned_to: ANALYST }));
    await updateAlert(auth(), ID, { assigned_to: "me" }, request);

    expect(repo.updateAlertRow).toHaveBeenCalledWith(
      expect.anything(),
      ID,
      { assigned_to: ANALYST },
      undefined,
    );
    expect(audit.mock.calls.map(([entry]) => entry.action)).toEqual(["alert.assigned"]);
  });

  it("only assigns people who may work alerts (422)", async () => {
    team.findMember.mockResolvedValue(null);
    const error = await failureOf(
      updateAlert(auth(), ID, { assigned_to: "0b8f4f3e-2f4e-4c55-9e0a-000000000001" }, request),
    );
    expect(error).toMatchObject({ status: 422 });
    expect(repo.updateAlertRow).not.toHaveBeenCalled();
  });

  it("unassigns with null", async () => {
    repo.findAlertRow.mockResolvedValue(alert({ assigned_to: ANALYST, status: "acknowledged" }));
    repo.updateAlertRow.mockResolvedValue(alert({ assigned_to: null, status: "acknowledged" }));
    await updateAlert(auth(), ID, { assigned_to: null }, request);
    expect(repo.updateAlertRow).toHaveBeenCalledWith(
      expect.anything(),
      ID,
      { assigned_to: null },
      undefined,
    );
  });

  it("treats a malformed or unknown id as not found, without touching the database for the first", async () => {
    expect(
      await failureOf(updateAlert(auth(), "nope", { status: "acknowledged" }, request)),
    ).toMatchObject({ status: 404 });
    expect(repo.findAlertRow).not.toHaveBeenCalled();

    repo.findAlertRow.mockResolvedValue(null);
    expect(
      await failureOf(updateAlert(auth(), ID, { status: "acknowledged" }, request)),
    ).toMatchObject({ status: 404 });
  });
});

describe("createAlert, getAlert and deleteAlert", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
  });

  it("records a created alert in the audit log with its provenance", async () => {
    repo.insertAlert.mockResolvedValue(alert({ origin: "local", source: "manual" }));
    repo.findAlertDetail.mockResolvedValue({ ...alert(), investigations: [] });
    await createAlert(auth(), { title: "Beacon to 203.0.113.9" }, request);

    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "alert.created",
        entityType: "alert",
        entityId: ID,
        metadata: { title: "Beacon to 203.0.113.9", severity: "high", origin: "local" },
      }),
      request,
    );
  });

  it("answers 404 for a malformed id and for an alert the caller cannot see", async () => {
    expect(await failureOf(getAlert({} as AuthClient, "nope"))).toMatchObject({ status: 404 });
    repo.findAlertDetail.mockResolvedValue(null);
    expect(await failureOf(getAlert({} as AuthClient, ID))).toMatchObject({ status: 404 });
  });

  it("deletes an alert, audits it, and answers 404 when it was already gone", async () => {
    repo.deleteAlertRow.mockResolvedValueOnce({ id: ID, title: "Beacon", origin: "demo" });
    await deleteAlert(auth(), ID, request);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "alert.deleted",
        metadata: { title: "Beacon", origin: "demo" },
      }),
      request,
    );

    repo.deleteAlertRow.mockResolvedValueOnce(null);
    expect(await failureOf(deleteAlert(auth(), ID, request))).toMatchObject({ status: 404 });
  });
});
