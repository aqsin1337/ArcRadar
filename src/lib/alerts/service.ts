import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { findMember } from "@/lib/team/repository";
import { ALERT_STATUS_LABELS, ASSIGNEE_ME } from "./constants";
import {
  deleteAlertRow,
  findAlertDetail,
  findAlertRow,
  findAlertSources,
  findAlertStats,
  findAlerts,
  insertAlert,
  updateAlertRow,
} from "./repository";
import {
  alertIdSchema,
  type AlertListQuery,
  type CreateAlertInput,
  type UpdateAlertInput,
} from "./schema";
import type { AlertDetail, AlertListItem, AlertStats } from "./types";
import { buildStatusPatch, canTransition } from "./workflow";

type RequestLike = { headers: Headers };

/** Page-level check for ids taken from a URL: a malformed id is simply "not found". */
export const isAlertId = (id: string) => alertIdSchema.safeParse(id).success;

export async function listAlerts(
  auth: AuthContext,
  query: AlertListQuery,
): Promise<Page<AlertListItem>> {
  const { rows, total } = await findAlerts(auth.supabase, query, auth.user.id);
  return buildPage(rows, total, query);
}

export const getAlertStats = (supabase: AuthClient): Promise<AlertStats> =>
  findAlertStats(supabase);
export const listAlertSources = (supabase: AuthClient): Promise<string[]> =>
  findAlertSources(supabase);

export async function getAlert(supabase: AuthClient, id: string): Promise<AlertDetail> {
  if (!isAlertId(id)) throw apiErrors.notFound("Alert not found.");
  const detail = await findAlertDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Alert not found.");
  return detail;
}

/** Creates a manual, local alert. Live alerts (a sensor, a scanner) arrive through ingestion, not here. */
export async function createAlert(
  auth: AuthContext,
  input: CreateAlertInput,
  request: RequestLike,
): Promise<AlertDetail> {
  const row = await insertAlert(auth.supabase, input);
  await writeAuditLog(
    {
      action: "alert.created",
      userId: auth.user.id,
      entityType: "alert",
      entityId: row.id,
      metadata: { title: row.title, severity: row.severity, origin: row.origin },
    },
    request,
  );
  return getAlert(auth.supabase, row.id);
}

/** Only active people who may work alerts can be given one. */
async function assertAssignable(supabase: AuthClient, userId: string) {
  if (!(await findMember(supabase, userId, "alerts:write"))) {
    throw apiErrors.validation({
      issues: [{ path: "assigned_to", message: "That person cannot be assigned alerts." }],
    });
  }
}

/**
 * Moves an alert through its lifecycle and/or assigns it. The move follows the state machine in
 * `workflow.ts` (anything else is a 409), the timestamps are worked out there in one place, and the
 * update only applies while the alert is still in the status the caller saw (a concurrent change is a 409).
 */
export async function updateAlert(
  auth: AuthContext,
  id: string,
  input: UpdateAlertInput,
  request: RequestLike,
  now: () => Date = () => new Date(),
): Promise<AlertDetail> {
  if (!isAlertId(id)) throw apiErrors.notFound("Alert not found.");
  const { supabase } = auth;

  const current = await findAlertRow(supabase, id);
  if (!current) throw apiErrors.notFound("Alert not found.");

  let patch: Parameters<typeof updateAlertRow>[2] = {};
  const nextStatus =
    input.status !== undefined && input.status !== current.status ? input.status : null;
  if (nextStatus) {
    if (!canTransition(current.status, nextStatus)) {
      throw apiErrors.conflict(
        `An alert that is ${ALERT_STATUS_LABELS[current.status].toLowerCase()} cannot become ${ALERT_STATUS_LABELS[nextStatus].toLowerCase()}.`,
      );
    }
    patch = buildStatusPatch(current, nextStatus, now(), auth.user.id);
  }

  let assignee = current.assigned_to;
  if (input.assigned_to !== undefined) {
    assignee = input.assigned_to === ASSIGNEE_ME ? auth.user.id : input.assigned_to;
    if (assignee !== null && assignee !== current.assigned_to)
      await assertAssignable(supabase, assignee);
    patch = { ...patch, assigned_to: assignee };
  }
  if (patch.assigned_to === current.assigned_to) delete patch.assigned_to;

  if (Object.keys(patch).length > 0) {
    const updated = await updateAlertRow(
      supabase,
      id,
      patch,
      nextStatus ? current.status : undefined,
    );
    if (!updated) {
      throw apiErrors.conflict("This alert was changed by someone else. Reload it and try again.");
    }

    if (nextStatus) {
      await writeAuditLog(
        {
          action: "alert.status_changed",
          userId: auth.user.id,
          entityType: "alert",
          entityId: id,
          metadata: { title: current.title, from: current.status, to: nextStatus },
        },
        request,
      );
    }
    if (updated.assigned_to !== current.assigned_to) {
      await writeAuditLog(
        {
          action: "alert.assigned",
          userId: auth.user.id,
          entityType: "alert",
          entityId: id,
          metadata: { title: current.title, from: current.assigned_to, to: updated.assigned_to },
        },
        request,
      );
    }
  }

  return getAlert(supabase, id);
}

export async function deleteAlert(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isAlertId(id)) throw apiErrors.notFound("Alert not found.");
  const removed = await deleteAlertRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Alert not found.");

  await writeAuditLog(
    {
      action: "alert.deleted",
      userId: auth.user.id,
      entityType: "alert",
      entityId: id,
      metadata: { title: removed.title, origin: removed.origin },
    },
    request,
  );
}
