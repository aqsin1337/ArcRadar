import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { ASSIGNEE_ME } from "@/lib/alerts/constants";
import { findAlertRow, updateAlertRow } from "@/lib/alerts/repository";
import { buildStatusPatch } from "@/lib/alerts/workflow";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { logError } from "@/lib/log";
import { findDisplayNames, findMember } from "@/lib/team/repository";
import type { Investigation } from "@/types/domain";
import { INVESTIGATION_STATUS_LABELS, PRIORITY_LABELS } from "./constants";
import {
  deleteAlertLink,
  deleteChecklistItemRow,
  deleteEvidenceRow,
  deleteIndicatorLink,
  deleteInvestigationRow,
  deleteNoteRow,
  findChecklistItems,
  findInvestigationDetail,
  findInvestigationRow,
  findInvestigationStats,
  findInvestigations,
  findLinkLabel,
  findNote,
  insertAlertLinks,
  insertChecklistItem,
  insertEvidence,
  insertIndicatorLinks,
  insertInvestigation,
  insertNote,
  insertSystemNote,
  replaceInvestigationTags,
  updateChecklistItemRow,
  updateInvestigationRow,
  updateNoteRow,
} from "./repository";
import {
  investigationIdSchema,
  subIdSchema,
  type CreateChecklistItemInput,
  type CreateInvestigationInput,
  type EvidenceInput,
  type InvestigationListQuery,
  type NoteInput,
  type UpdateInvestigationInput,
} from "./schema";
import type {
  ChecklistItem,
  InvestigationDetail,
  InvestigationListItem,
  InvestigationStats,
} from "./types";

type RequestLike = { headers: Headers };

/** Page-level check for ids taken from a URL: a malformed id is simply "not found". */
export const isInvestigationId = (id: string) => investigationIdSchema.safeParse(id).success;

export async function listInvestigations(
  auth: AuthContext,
  query: InvestigationListQuery,
): Promise<Page<InvestigationListItem>> {
  const { rows, total } = await findInvestigations(auth.supabase, query, auth.user.id);
  return buildPage(rows, total, query);
}

export const getInvestigationStats = (supabase: AuthClient): Promise<InvestigationStats> =>
  findInvestigationStats(supabase);

export async function getInvestigation(
  supabase: AuthClient,
  id: string,
): Promise<InvestigationDetail> {
  if (!isInvestigationId(id)) throw apiErrors.notFound("Investigation not found.");
  const detail = await findInvestigationDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Investigation not found.");
  return detail;
}

async function requireInvestigation(supabase: AuthClient, id: string): Promise<Investigation> {
  if (!isInvestigationId(id)) throw apiErrors.notFound("Investigation not found.");
  const row = await findInvestigationRow(supabase, id);
  if (!row) throw apiErrors.notFound("Investigation not found.");
  return row;
}

/** `me`, a person who may work investigations, or nobody. */
async function resolveAnalyst(
  auth: AuthContext,
  value: string | null,
  current: string | null,
): Promise<string | null> {
  const id = value === ASSIGNEE_ME ? auth.user.id : value;
  if (
    id !== null &&
    id !== current &&
    !(await findMember(auth.supabase, id, "investigations:write"))
  ) {
    throw apiErrors.validation({
      issues: [{ path: "analyst_id", message: "That person cannot work investigations." }],
    });
  }
  return id;
}

/** The status history is best effort: a failure to record it must not undo the change it describes. */
async function recordHistory(investigationId: string, actorId: string, text: string) {
  try {
    await insertSystemNote(investigationId, actorId, text);
  } catch (error) {
    logError("investigation.history_failed", error, { investigation_id: investigationId });
  }
}

/** Bumps `updated_at` so the list shows recent activity first (notes, evidence and links are separate rows). */
async function touch(supabase: AuthClient, investigation: Pick<Investigation, "id" | "title">) {
  await updateInvestigationRow(supabase, investigation.id, { title: investigation.title }).catch(
    () => null,
  );
}

/**
 * An alert attached to an investigation is being worked on: a `new` or `acknowledged` alert moves to
 * `investigating` (through the same lifecycle rules as any other change). Alerts in any other status
 * are left alone, and so is one that somebody else changed in the meantime.
 */
async function startWorkOnAlerts(auth: AuthContext, alertIds: string[], request: RequestLike) {
  for (const alertId of alertIds) {
    const alert = await findAlertRow(auth.supabase, alertId);
    if (!alert || (alert.status !== "new" && alert.status !== "acknowledged")) continue;

    const patch = buildStatusPatch(alert, "investigating", new Date(), auth.user.id);
    const updated = await updateAlertRow(auth.supabase, alertId, patch, alert.status);
    if (!updated) continue;
    await writeAuditLog(
      {
        action: "alert.status_changed",
        userId: auth.user.id,
        entityType: "alert",
        entityId: alertId,
        metadata: {
          title: alert.title,
          from: alert.status,
          to: "investigating",
          reason: "attached to an investigation",
        },
      },
      request,
    );
  }
}

/** Every id must exist (and be visible), so a bad id fails before anything has been created. */
async function assertAllExist(
  supabase: AuthClient,
  table: "indicators" | "alerts",
  ids: string[],
  field: "indicator_ids" | "alert_ids",
) {
  if (ids.length === 0) return;
  const { data, error } = await supabase.from(table).select("id").in("id", ids);
  if (error) throw apiErrors.internal();
  if (data.length !== ids.length) {
    throw apiErrors.validation({
      issues: [{ path: field, message: `One of the ${table} does not exist.` }],
    });
  }
}

/**
 * Opens an investigation (always `open`, always local). It can start with tags, indicators and
 * alerts; attaching alerts moves them to `investigating`. The analyst defaults to the caller.
 */
export async function createInvestigation(
  auth: AuthContext,
  input: CreateInvestigationInput,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const { supabase } = auth;
  const indicatorIds = input.indicator_ids ?? [];
  const alertIds = input.alert_ids ?? [];
  await assertAllExist(supabase, "indicators", indicatorIds, "indicator_ids");
  await assertAllExist(supabase, "alerts", alertIds, "alert_ids");

  const analyst = await resolveAnalyst(
    auth,
    input.analyst_id === undefined ? auth.user.id : input.analyst_id,
    null,
  );
  const row = await insertInvestigation(supabase, {
    title: input.title,
    description: input.description,
    priority: input.priority,
    analyst_id: analyst,
  });

  if (input.tags && input.tags.length > 0)
    await replaceInvestigationTags(supabase, row.id, input.tags);
  await insertIndicatorLinks(supabase, row.id, indicatorIds);
  await insertAlertLinks(supabase, row.id, alertIds);
  await startWorkOnAlerts(auth, alertIds, request);

  await writeAuditLog(
    {
      action: "investigation.created",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: row.id,
      metadata: {
        title: row.title,
        priority: row.priority,
        indicators: indicatorIds.length,
        alerts: alertIds.length,
      },
    },
    request,
  );
  return getInvestigation(supabase, row.id);
}

/**
 * Changes an investigation. A change of status, priority or analyst leaves a line of history (a
 * `system` note that clients cannot forge); closing sets `closed_at` and leaving `closed` clears it.
 */
export async function updateInvestigation(
  auth: AuthContext,
  id: string,
  input: UpdateInvestigationInput,
  request: RequestLike,
  now: () => Date = () => new Date(),
): Promise<InvestigationDetail> {
  const { supabase } = auth;
  const current = await requireInvestigation(supabase, id);
  const { tags, ...fields } = input;

  const patch: Parameters<typeof updateInvestigationRow>[2] = {};
  const history: string[] = [];

  if (fields.title !== undefined && fields.title !== current.title) patch.title = fields.title;
  if (fields.description !== undefined && fields.description !== current.description) {
    patch.description = fields.description;
  }
  if (fields.priority !== undefined && fields.priority !== current.priority) {
    patch.priority = fields.priority;
    history.push(
      `Priority changed from ${PRIORITY_LABELS[current.priority]} to ${PRIORITY_LABELS[fields.priority]}.`,
    );
  }
  if (fields.status !== undefined && fields.status !== current.status) {
    patch.status = fields.status;
    patch.closed_at = fields.status === "closed" ? now().toISOString() : null;
    history.push(
      `Status changed from ${INVESTIGATION_STATUS_LABELS[current.status]} to ${INVESTIGATION_STATUS_LABELS[fields.status]}.`,
    );
  }
  if (fields.analyst_id !== undefined) {
    const analyst = await resolveAnalyst(auth, fields.analyst_id, current.analyst_id);
    if (analyst !== current.analyst_id) {
      patch.analyst_id = analyst;
      const names = await findDisplayNames(supabase, [analyst]);
      history.push(
        analyst === null
          ? "Unassigned."
          : `Assigned to ${names.get(analyst)?.trim() || "a teammate"}.`,
      );
    }
  }

  const updated = await updateInvestigationRow(supabase, id, patch);
  if (!updated) throw apiErrors.notFound("Investigation not found.");
  if (tags) await replaceInvestigationTags(supabase, id, tags);
  for (const line of history) await recordHistory(id, auth.user.id, line);

  const changed = [
    ...Object.keys(patch).filter((key) => key !== "closed_at"),
    ...(tags ? ["tags"] : []),
  ];
  if (changed.length > 0) {
    await writeAuditLog(
      {
        action: "investigation.updated",
        userId: auth.user.id,
        entityType: "investigation",
        entityId: id,
        metadata: {
          title: updated.title,
          fields: changed,
          ...(patch.status ? { status_from: current.status, status_to: patch.status } : {}),
        },
      },
      request,
    );
  }
  return getInvestigation(supabase, id);
}

export async function deleteInvestigation(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isInvestigationId(id)) throw apiErrors.notFound("Investigation not found.");
  const removed = await deleteInvestigationRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Investigation not found.");

  await writeAuditLog(
    {
      action: "investigation.deleted",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: removed.title, origin: removed.origin },
    },
    request,
  );
}

// --- indicators and alerts ---------------------------------------------------------------------------------

async function auditLink(
  auth: AuthContext,
  request: RequestLike,
  action: "investigation.link_added" | "investigation.link_removed",
  investigation: Investigation,
  kind: "indicator" | "alert",
  targetId: string,
  label: string | null,
) {
  await writeAuditLog(
    {
      action,
      userId: auth.user.id,
      entityType: "investigation",
      entityId: investigation.id,
      metadata: { title: investigation.title, kind, target_id: targetId, target: label },
    },
    request,
  );
}

export async function attachIndicator(
  auth: AuthContext,
  id: string,
  indicatorId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  await insertIndicatorLinks(auth.supabase, id, [indicatorId]);
  await touch(auth.supabase, investigation);
  await auditLink(
    auth,
    request,
    "investigation.link_added",
    investigation,
    "indicator",
    indicatorId,
    await findLinkLabel(auth.supabase, "indicator", indicatorId),
  );
  return getInvestigation(auth.supabase, id);
}

export async function detachIndicator(
  auth: AuthContext,
  id: string,
  indicatorId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  if (!subIdSchema.safeParse(indicatorId).success) throw apiErrors.notFound("Indicator not found.");
  const label = await findLinkLabel(auth.supabase, "indicator", indicatorId);
  if (!(await deleteIndicatorLink(auth.supabase, id, indicatorId))) {
    throw apiErrors.notFound("That indicator is not attached to this investigation.");
  }
  await touch(auth.supabase, investigation);
  await auditLink(
    auth,
    request,
    "investigation.link_removed",
    investigation,
    "indicator",
    indicatorId,
    label,
  );
  return getInvestigation(auth.supabase, id);
}

export async function attachAlert(
  auth: AuthContext,
  id: string,
  alertId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  await insertAlertLinks(auth.supabase, id, [alertId]);
  await startWorkOnAlerts(auth, [alertId], request);
  await touch(auth.supabase, investigation);
  await auditLink(
    auth,
    request,
    "investigation.link_added",
    investigation,
    "alert",
    alertId,
    await findLinkLabel(auth.supabase, "alert", alertId),
  );
  return getInvestigation(auth.supabase, id);
}

export async function detachAlert(
  auth: AuthContext,
  id: string,
  alertId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  if (!subIdSchema.safeParse(alertId).success) throw apiErrors.notFound("Alert not found.");
  const label = await findLinkLabel(auth.supabase, "alert", alertId);
  if (!(await deleteAlertLink(auth.supabase, id, alertId))) {
    throw apiErrors.notFound("That alert is not attached to this investigation.");
  }
  await touch(auth.supabase, investigation);
  await auditLink(
    auth,
    request,
    "investigation.link_removed",
    investigation,
    "alert",
    alertId,
    label,
  );
  return getInvestigation(auth.supabase, id);
}

// --- notes and evidence ----------------------------------------------------------------------------------------

export async function addNote(
  auth: AuthContext,
  id: string,
  input: NoteInput,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  const note = await insertNote(auth.supabase, id, input.body);
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.note_added",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, note_id: note.id },
    },
    request,
  );
  return getInvestigation(auth.supabase, id);
}

/** Ordinary notes belong to their author (row level security); the status history is nobody's to change. */
async function requireOwnNote(auth: AuthContext, id: string, noteId: string, mayModerate: boolean) {
  if (!subIdSchema.safeParse(noteId).success) throw apiErrors.notFound("Note not found.");
  const note = await findNote(auth.supabase, id, noteId);
  if (!note) throw apiErrors.notFound("Note not found.");
  if (note.kind === "system") throw apiErrors.forbidden("The status history cannot be changed.");
  if (note.author_id !== auth.user.id && !mayModerate) {
    throw apiErrors.forbidden("Only the author of a note can change it.");
  }
  return note;
}

export async function editNote(
  auth: AuthContext,
  id: string,
  noteId: string,
  input: NoteInput,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  await requireOwnNote(auth, id, noteId, false);
  if (!(await updateNoteRow(auth.supabase, noteId, input.body))) {
    throw apiErrors.notFound("Note not found.");
  }
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.note_updated",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, note_id: noteId },
    },
    request,
  );
  return getInvestigation(auth.supabase, id);
}

export async function removeNote(
  auth: AuthContext,
  id: string,
  noteId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  await requireOwnNote(auth, id, noteId, auth.permissions.has("investigations:delete"));
  if (!(await deleteNoteRow(auth.supabase, noteId))) throw apiErrors.notFound("Note not found.");
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.note_deleted",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, note_id: noteId },
    },
    request,
  );
  return getInvestigation(auth.supabase, id);
}

export async function addEvidence(
  auth: AuthContext,
  id: string,
  input: EvidenceInput,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  const evidence = await insertEvidence(auth.supabase, id, input);
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.evidence_added",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, evidence_id: evidence.id, evidence: input.title },
    },
    request,
  );
  return getInvestigation(auth.supabase, id);
}

export async function removeEvidence(
  auth: AuthContext,
  id: string,
  evidenceId: string,
  request: RequestLike,
): Promise<InvestigationDetail> {
  const investigation = await requireInvestigation(auth.supabase, id);
  if (!subIdSchema.safeParse(evidenceId).success) throw apiErrors.notFound("Evidence not found.");
  const removed = await deleteEvidenceRow(auth.supabase, id, evidenceId);
  if (!removed) throw apiErrors.notFound("Evidence not found.");
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.evidence_removed",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, evidence_id: evidenceId, evidence: removed.title },
    },
    request,
  );
  return getInvestigation(auth.supabase, id);
}

// --- checklist -----------------------------------------------------------------------------------------

export async function getChecklist(supabase: AuthClient, id: string): Promise<ChecklistItem[]> {
  if (!isInvestigationId(id)) throw apiErrors.notFound("Investigation not found.");
  return findChecklistItems(supabase, id);
}

export async function addChecklistItem(
  auth: AuthContext,
  id: string,
  input: CreateChecklistItemInput,
  request: RequestLike,
): Promise<ChecklistItem[]> {
  const investigation = await requireInvestigation(auth.supabase, id);
  await insertChecklistItem(auth.supabase, id, input.text, "analyst");
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.checklist_item_added",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, text: input.text, source: "analyst" },
    },
    request,
  );
  return getChecklist(auth.supabase, id);
}

/** Toggles one item done/not-done; the server (not the client) records who and when. */
export async function toggleChecklistItem(
  auth: AuthContext,
  id: string,
  itemId: string,
  done: boolean,
  request: RequestLike,
  now: () => Date = () => new Date(),
): Promise<ChecklistItem[]> {
  const investigation = await requireInvestigation(auth.supabase, id);
  if (!subIdSchema.safeParse(itemId).success) throw apiErrors.notFound("Checklist item not found.");
  const updated = await updateChecklistItemRow(auth.supabase, itemId, {
    done,
    done_by: done ? auth.user.id : null,
    done_at: done ? now().toISOString() : null,
  });
  if (!updated) throw apiErrors.notFound("Checklist item not found.");
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.checklist_item_updated",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, item_id: itemId, done },
    },
    request,
  );
  return getChecklist(auth.supabase, id);
}

export async function removeChecklistItem(
  auth: AuthContext,
  id: string,
  itemId: string,
  request: RequestLike,
): Promise<ChecklistItem[]> {
  const investigation = await requireInvestigation(auth.supabase, id);
  if (!subIdSchema.safeParse(itemId).success) throw apiErrors.notFound("Checklist item not found.");
  if (!(await deleteChecklistItemRow(auth.supabase, id, itemId))) {
    throw apiErrors.notFound("Checklist item not found.");
  }
  await touch(auth.supabase, investigation);
  await writeAuditLog(
    {
      action: "investigation.checklist_item_removed",
      userId: auth.user.id,
      entityType: "investigation",
      entityId: id,
      metadata: { title: investigation.title, item_id: itemId },
    },
    request,
  );
  return getChecklist(auth.supabase, id);
}
