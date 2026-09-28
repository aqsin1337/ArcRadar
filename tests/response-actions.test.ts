import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import {
  canTransitionResponseAction,
  RESPONSE_ACTION_TRANSITIONS,
} from "@/lib/response-actions/constants";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  deleteLogEntryRow: vi.fn(),
  deleteResponseActionRow: vi.fn(),
  findLogEntryRow: vi.fn(),
  findLogForAlert: vi.fn(),
  findResponseActions: vi.fn(),
  insertLogEntry: vi.fn(),
  insertResponseAction: vi.fn(),
  updateLogEntryRow: vi.fn(),
  updateResponseActionRow: vi.fn(),
}));
const alertsService = vi.hoisted(() => ({ getAlert: vi.fn(), isAlertId: vi.fn(() => true) }));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock("@/lib/response-actions/repository", () => repo);
vi.mock("@/lib/alerts/service", () => alertsService);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const {
  attachResponseAction,
  createResponseAction,
  deleteResponseAction,
  removeResponseActionLog,
  updateResponseAction,
  updateResponseActionLog,
} = await import("@/lib/response-actions/service");

const request = { headers: new Headers() };
const ALERT_ID = "5c1f7d20-8d4b-4a53-8a1e-2b7f9c0d1e3f";
const LOG_ID = "9a3c2e10-1b7d-4e6f-a0c4-5d8e7f6a4b3c";
const ACTION_ID = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const NOW = new Date("2026-09-28T10:00:00.000Z");

const auth = (role: "admin" | "analyst" | "viewer" = "analyst"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: `${role}@arcradar.test` },
  profile: { display_name: role, role },
  permissions: permissionsForRole(role),
});

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected the call to fail");
}

beforeEach(() => {
  vi.clearAllMocks();
  audit.mockResolvedValue(true);
  alertsService.getAlert.mockResolvedValue({ id: ALERT_ID });
});

describe("the response-action workflow", () => {
  it("only ever moves forward: recommended -> acknowledged/completed/skipped -> a closed state", () => {
    expect(canTransitionResponseAction("recommended", "acknowledged")).toBe(true);
    expect(canTransitionResponseAction("recommended", "completed")).toBe(true);
    expect(canTransitionResponseAction("acknowledged", "completed")).toBe(true);
    expect(canTransitionResponseAction("completed", "acknowledged")).toBe(false);
    expect(canTransitionResponseAction("skipped", "recommended")).toBe(false);
    expect(RESPONSE_ACTION_TRANSITIONS.completed).toEqual([]);
    expect(RESPONSE_ACTION_TRANSITIONS.skipped).toEqual([]);
  });
});

describe("the catalog", () => {
  it("creates, updates and audits an entry", async () => {
    repo.insertResponseAction.mockResolvedValue({ id: ACTION_ID, title: "Isolate the host" });
    const created = await createResponseAction(auth(), { title: "Isolate the host" }, request);
    expect(created.id).toBe(ACTION_ID);
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({ action: "response_action.created" });

    repo.updateResponseActionRow.mockResolvedValue({
      id: ACTION_ID,
      title: "Isolate the endpoint",
    });
    await updateResponseAction(auth(), ACTION_ID, { title: "Isolate the endpoint" }, request);
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({ action: "response_action.updated" });
  });

  it("404s updating or deleting an unknown action", async () => {
    repo.updateResponseActionRow.mockResolvedValue(null);
    expect(
      await failureOf(updateResponseAction(auth(), ACTION_ID, { title: "x" }, request)),
    ).toMatchObject({ status: 404 });

    repo.deleteResponseActionRow.mockResolvedValue(null);
    expect(await failureOf(deleteResponseAction(auth(), ACTION_ID, request))).toMatchObject({
      status: 404,
    });
  });
});

describe("the per-alert log", () => {
  it("attaching an existing action starts it as recommended, source analyst, and audits it", async () => {
    repo.insertLogEntry.mockResolvedValue(undefined);
    repo.findLogForAlert.mockResolvedValue([]);
    await attachResponseAction(auth(), ALERT_ID, ACTION_ID, request);
    expect(repo.insertLogEntry).toHaveBeenCalledWith(expect.anything(), {
      actionId: ACTION_ID,
      alertId: ALERT_ID,
      status: "recommended",
      source: "analyst",
    });
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({ action: "response_action.attached" });
  });

  it("moves a recommendation forward, stamping who and when", async () => {
    repo.findLogEntryRow.mockResolvedValue({
      id: LOG_ID,
      alert_id: ALERT_ID,
      status: "recommended",
      notes: null,
    });
    repo.updateLogEntryRow.mockResolvedValue(true);
    repo.findLogForAlert.mockResolvedValue([]);

    await updateResponseActionLog(
      auth(),
      ALERT_ID,
      LOG_ID,
      { status: "acknowledged" },
      request,
      () => NOW,
    );
    expect(repo.updateLogEntryRow).toHaveBeenCalledWith(expect.anything(), LOG_ID, {
      status: "acknowledged",
      notes: null,
      performed_by: "user-1",
      performed_at: NOW.toISOString(),
    });
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({
      action: "response_action.status_changed",
      metadata: expect.objectContaining({ from: "recommended", to: "acknowledged" }),
    });
  });

  it("keeps existing notes when none are given, and can update them", async () => {
    repo.findLogEntryRow.mockResolvedValue({
      id: LOG_ID,
      alert_id: ALERT_ID,
      status: "recommended",
      notes: "already noted",
    });
    repo.updateLogEntryRow.mockResolvedValue(true);
    repo.findLogForAlert.mockResolvedValue([]);

    await updateResponseActionLog(
      auth(),
      ALERT_ID,
      LOG_ID,
      { status: "recommended" },
      request,
      () => NOW,
    );
    expect(repo.updateLogEntryRow).toHaveBeenCalledWith(
      expect.anything(),
      LOG_ID,
      expect.objectContaining({ notes: "already noted" }),
    );
  });

  it("409s a move the workflow does not allow, and changes nothing", async () => {
    repo.findLogEntryRow.mockResolvedValue({
      id: LOG_ID,
      alert_id: ALERT_ID,
      status: "completed",
      notes: null,
    });
    expect(
      await failureOf(
        updateResponseActionLog(auth(), ALERT_ID, LOG_ID, { status: "acknowledged" }, request),
      ),
    ).toMatchObject({ status: 409 });
    expect(repo.updateLogEntryRow).not.toHaveBeenCalled();
  });

  it("404s a log entry that belongs to a different alert", async () => {
    repo.findLogEntryRow.mockResolvedValue({
      id: LOG_ID,
      alert_id: "different-alert",
      status: "recommended",
      notes: null,
    });
    expect(
      await failureOf(
        updateResponseActionLog(auth(), ALERT_ID, LOG_ID, { status: "acknowledged" }, request),
      ),
    ).toMatchObject({ status: 404 });
  });

  it("removes a log entry", async () => {
    repo.deleteLogEntryRow.mockResolvedValue(true);
    repo.findLogForAlert.mockResolvedValue([]);
    await removeResponseActionLog(auth(), ALERT_ID, LOG_ID, request);
    expect(repo.deleteLogEntryRow).toHaveBeenCalledWith(expect.anything(), ALERT_ID, LOG_ID);
  });

  it("404s removing a log entry that does not exist", async () => {
    repo.deleteLogEntryRow.mockResolvedValue(false);
    expect(
      await failureOf(removeResponseActionLog(auth(), ALERT_ID, LOG_ID, request)),
    ).toMatchObject({
      status: 404,
    });
  });
});
