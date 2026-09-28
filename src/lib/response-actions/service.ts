import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { getAlert, isAlertId } from "@/lib/alerts/service";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { canTransitionResponseAction, RESPONSE_ACTION_STATUS_LABELS } from "./constants";
import {
  deleteLogEntryRow,
  deleteResponseActionRow,
  findLogEntryRow,
  findLogForAlert,
  findResponseActions,
  insertLogEntry,
  insertResponseAction,
  updateLogEntryRow,
  updateResponseActionRow,
} from "./repository";
import {
  responseActionIdSchema,
  responseActionLogIdSchema,
  type CreateResponseActionInput,
  type UpdateResponseActionInput,
  type UpdateResponseActionLogInput,
} from "./schema";
import type { ResponseAction, ResponseActionLogEntry } from "./types";

type RequestLike = { headers: Headers };

export const listResponseActions = (supabase: AuthClient): Promise<ResponseAction[]> =>
  findResponseActions(supabase);

export async function createResponseAction(
  auth: AuthContext,
  input: CreateResponseActionInput,
  request: RequestLike,
): Promise<ResponseAction> {
  const row = await insertResponseAction(auth.supabase, input);
  await writeAuditLog(
    {
      action: "response_action.created",
      userId: auth.user.id,
      entityType: "response_action",
      entityId: row.id,
      metadata: { title: row.title, category: row.category },
    },
    request,
  );
  return row;
}

export async function updateResponseAction(
  auth: AuthContext,
  id: string,
  input: UpdateResponseActionInput,
  request: RequestLike,
): Promise<ResponseAction> {
  if (!responseActionIdSchema.safeParse(id).success) {
    throw apiErrors.notFound("Response action not found.");
  }
  const row = await updateResponseActionRow(auth.supabase, id, input);
  if (!row) throw apiErrors.notFound("Response action not found.");
  await writeAuditLog(
    {
      action: "response_action.updated",
      userId: auth.user.id,
      entityType: "response_action",
      entityId: id,
      metadata: { title: row.title, fields: Object.keys(input) },
    },
    request,
  );
  return row;
}

export async function deleteResponseAction(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!responseActionIdSchema.safeParse(id).success) {
    throw apiErrors.notFound("Response action not found.");
  }
  const removed = await deleteResponseActionRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Response action not found.");
  await writeAuditLog(
    {
      action: "response_action.deleted",
      userId: auth.user.id,
      entityType: "response_action",
      entityId: id,
      metadata: { title: removed.title },
    },
    request,
  );
}

// --- the per-alert log ---------------------------------------------------------------------------------

export async function listAlertResponseActions(
  supabase: AuthClient,
  alertId: string,
): Promise<ResponseActionLogEntry[]> {
  if (!isAlertId(alertId)) throw apiErrors.notFound("Alert not found.");
  return findLogForAlert(supabase, alertId);
}

/** An analyst manually recommends an existing catalog action for this alert. */
export async function attachResponseAction(
  auth: AuthContext,
  alertId: string,
  actionId: string,
  request: RequestLike,
): Promise<ResponseActionLogEntry[]> {
  await getAlert(auth.supabase, alertId); // 404s an unknown or unreadable alert
  await insertLogEntry(auth.supabase, {
    actionId,
    alertId,
    status: "recommended",
    source: "analyst",
  });
  await writeAuditLog(
    {
      action: "response_action.attached",
      userId: auth.user.id,
      entityType: "alert",
      entityId: alertId,
      metadata: { action_id: actionId },
    },
    request,
  );
  return listAlertResponseActions(auth.supabase, alertId);
}

/**
 * Moves a recommendation through recommended -> acknowledged -> completed/skipped (never backwards,
 * the same idea as the alert lifecycle); notes can be added at any step.
 */
export async function updateResponseActionLog(
  auth: AuthContext,
  alertId: string,
  logId: string,
  input: UpdateResponseActionLogInput,
  request: RequestLike,
  now: () => Date = () => new Date(),
): Promise<ResponseActionLogEntry[]> {
  await getAlert(auth.supabase, alertId);
  if (!responseActionLogIdSchema.safeParse(logId).success) {
    throw apiErrors.notFound("Response action log entry not found.");
  }
  const current = await findLogEntryRow(auth.supabase, logId);
  if (!current || current.alert_id !== alertId) {
    throw apiErrors.notFound("Response action log entry not found.");
  }

  if (
    input.status !== current.status &&
    !canTransitionResponseAction(current.status, input.status)
  ) {
    throw apiErrors.conflict(
      `An action that is ${RESPONSE_ACTION_STATUS_LABELS[current.status].toLowerCase()} cannot become ${RESPONSE_ACTION_STATUS_LABELS[input.status].toLowerCase()}.`,
    );
  }

  const acted = input.status !== "recommended";
  const updated = await updateLogEntryRow(auth.supabase, logId, {
    status: input.status,
    notes: input.notes !== undefined ? input.notes : current.notes,
    performed_by: acted ? auth.user.id : null,
    performed_at: acted ? now().toISOString() : null,
  });
  if (!updated) throw apiErrors.notFound("Response action log entry not found.");

  if (input.status !== current.status) {
    await writeAuditLog(
      {
        action: "response_action.status_changed",
        userId: auth.user.id,
        entityType: "alert",
        entityId: alertId,
        metadata: { log_id: logId, from: current.status, to: input.status },
      },
      request,
    );
  }
  return listAlertResponseActions(auth.supabase, alertId);
}

export async function removeResponseActionLog(
  auth: AuthContext,
  alertId: string,
  logId: string,
  request: RequestLike,
): Promise<ResponseActionLogEntry[]> {
  await getAlert(auth.supabase, alertId);
  if (!responseActionLogIdSchema.safeParse(logId).success) {
    throw apiErrors.notFound("Response action log entry not found.");
  }
  if (!(await deleteLogEntryRow(auth.supabase, alertId, logId))) {
    throw apiErrors.notFound("Response action log entry not found.");
  }
  await writeAuditLog(
    {
      action: "response_action.status_changed",
      userId: auth.user.id,
      entityType: "alert",
      entityId: alertId,
      metadata: { log_id: logId, removed: true },
    },
    request,
  );
  return listAlertResponseActions(auth.supabase, alertId);
}
