import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findDisplayNames } from "@/lib/team/repository";
import type { CreateResponseActionInput, UpdateResponseActionInput } from "./schema";
import type { ResponseAction, ResponseActionLogEntry, ResponseActionStatus } from "./types";

/*
 * All queries use the caller's own client, so row level security is the final authority on what is
 * visible and writable.
 */

type ActionRow = {
  id: string;
  title: string;
  description: string | null;
  category: string | null;
  origin: ResponseAction["origin"];
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

async function toActions(supabase: AuthClient, rows: ActionRow[]): Promise<ResponseAction[]> {
  const names = await findDisplayNames(
    supabase,
    rows.map((row) => row.created_by),
  );
  return rows.map(({ created_by, ...row }) => ({
    ...row,
    created_by_name: created_by ? (names.get(created_by) ?? null) : null,
  }));
}

export async function findResponseActions(supabase: AuthClient): Promise<ResponseAction[]> {
  const { data, error } = await supabase.from("response_actions").select("*").order("title");
  if (error) throw toApiError(error);
  return toActions(supabase, data);
}

export async function insertResponseAction(
  supabase: AuthClient,
  input: CreateResponseActionInput,
): Promise<ResponseAction> {
  const { data, error } = await supabase
    .from("response_actions")
    .insert(input)
    .select("*")
    .single();
  if (error) throw toApiError(error);
  const [row] = await toActions(supabase, [data]);
  return row;
}

export async function updateResponseActionRow(
  supabase: AuthClient,
  id: string,
  patch: UpdateResponseActionInput,
): Promise<ResponseAction | null> {
  const { data, error } = await supabase
    .from("response_actions")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [row] = await toActions(supabase, [data]);
  return row;
}

export async function deleteResponseActionRow(
  supabase: AuthClient,
  id: string,
): Promise<{ id: string; title: string } | null> {
  const { data, error } = await supabase
    .from("response_actions")
    .delete()
    .eq("id", id)
    .select("id, title")
    .maybeSingle();
  if (error) {
    if (error.code === "23503") {
      throw apiErrors.conflict("This action has a history on an alert and cannot be deleted.");
    }
    throw toApiError(error);
  }
  return data;
}

// --- the per-alert log ---------------------------------------------------------------------------------

// action_id/status/source are `text` + a check constraint, not a Postgres enum, so PostgREST hands
// back a plain `string`; the check constraint is what actually guarantees a known value (the same
// reasoning ai_analyses' repository applies to `kind`/`subject_type`).
type LogRow = {
  id: string;
  action_id: string;
  status: string;
  source: string;
  notes: string | null;
  performed_by: string | null;
  performed_at: string | null;
  created_by: string | null;
  created_at: string;
  response_actions: { title: string; category: string | null } | null;
};

async function toLogEntries(
  supabase: AuthClient,
  rows: LogRow[],
): Promise<ResponseActionLogEntry[]> {
  const names = await findDisplayNames(supabase, [
    ...rows.map((row) => row.performed_by),
    ...rows.map((row) => row.created_by),
  ]);
  const nameOf = (userId: string | null) => (userId ? (names.get(userId) ?? null) : null);
  return rows.map((row) => ({
    id: row.id,
    action_id: row.action_id,
    action_title: row.response_actions?.title ?? "(deleted action)",
    action_category: row.response_actions?.category ?? null,
    status: row.status as ResponseActionStatus,
    source: row.source as ResponseActionLogEntry["source"],
    notes: row.notes,
    performed_by_name: nameOf(row.performed_by),
    performed_at: row.performed_at,
    created_by_name: nameOf(row.created_by),
    created_at: row.created_at,
  }));
}

const LOG_SELECT =
  "id, action_id, status, source, notes, performed_by, performed_at, created_by, created_at, response_actions(title, category)";

export async function findLogForAlert(
  supabase: AuthClient,
  alertId: string,
): Promise<ResponseActionLogEntry[]> {
  const { data, error } = await supabase
    .from("response_action_log")
    .select(LOG_SELECT)
    .eq("alert_id", alertId)
    .order("created_at", { ascending: true });
  if (error) throw toApiError(error);
  return toLogEntries(supabase, data);
}

export async function insertLogEntry(
  supabase: AuthClient,
  input: {
    actionId: string;
    alertId: string;
    status: ResponseActionStatus;
    source: "ai" | "analyst";
  },
): Promise<void> {
  const { error } = await supabase.from("response_action_log").insert({
    action_id: input.actionId,
    alert_id: input.alertId,
    status: input.status,
    source: input.source,
  });
  if (error) {
    if (error.code === "23503") {
      throw apiErrors.validation({
        issues: [{ path: "action_id", message: "That response action does not exist." }],
      });
    }
    throw toApiError(error);
  }
}

/** Seeds a catalog entry plus a 'recommended' log row for each AI-suggested action, in one go. */
export async function seedResponseActionsForAlert(
  supabase: AuthClient,
  alertId: string,
  actions: { title: string; why: string }[],
): Promise<void> {
  for (const suggestion of actions) {
    const { data: action, error: actionError } = await supabase
      .from("response_actions")
      .insert({ title: suggestion.title.slice(0, 200), description: suggestion.why.slice(0, 2000) })
      .select("id")
      .single();
    if (actionError) throw toApiError(actionError);
    await insertLogEntry(supabase, {
      actionId: action.id,
      alertId,
      status: "recommended",
      source: "ai",
    });
  }
}

export async function findLogEntryRow(
  supabase: AuthClient,
  logId: string,
): Promise<{
  id: string;
  alert_id: string | null;
  status: ResponseActionStatus;
  notes: string | null;
} | null> {
  const { data, error } = await supabase
    .from("response_action_log")
    .select("id, alert_id, status, notes")
    .eq("id", logId)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data ? { ...data, status: data.status as ResponseActionStatus } : null;
}

export async function updateLogEntryRow(
  supabase: AuthClient,
  logId: string,
  patch: {
    status: ResponseActionStatus;
    notes: string | null;
    performed_by: string | null;
    performed_at: string | null;
  },
): Promise<boolean> {
  const { data, error } = await supabase
    .from("response_action_log")
    .update(patch)
    .eq("id", logId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

export async function deleteLogEntryRow(
  supabase: AuthClient,
  alertId: string,
  logId: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("response_action_log")
    .delete()
    .eq("id", logId)
    .eq("alert_id", alertId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}
