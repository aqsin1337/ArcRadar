import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { createAdminClient } from "@/lib/supabase/admin";
import { findDisplayNames } from "@/lib/team/repository";
import type { Investigation } from "@/types/domain";
import { ASSIGNEE_ME, ASSIGNEE_NONE } from "@/lib/alerts/constants";
import { INVESTIGATION_STATUSES } from "./constants";
import type { EvidenceInput, InvestigationListQuery } from "./schema";
import { buildInvestigationTimeline } from "./timeline";
import type {
  InvestigationDetail,
  InvestigationListItem,
  InvestigationNote,
  InvestigationStats,
} from "./types";

/*
 * Reads and writes use the caller's own client, so row level security is the final authority on what
 * is visible and writable. The one exception is `insertSystemNote`: the status history is written by
 * the server (service role) after it has authorized the caller, so a client cannot forge it.
 */

const LIST_SELECT = `*,
  analyst:profiles!analyst_id(id, display_name),
  investigation_tags(tags(id, name, color)),
  investigation_indicators(count),
  investigation_alerts(count)`;

const DETAIL_SELECT = `*,
  analyst:profiles!analyst_id(id, display_name),
  investigation_tags(tags(id, name, color)),
  investigation_indicators(added_at, added_by, indicators(id, type, value, verdict, severity, origin)),
  investigation_alerts(added_at, added_by, alerts(id, title, severity, status, origin)),
  investigation_notes(id, author_id, kind, body, created_at, updated_at),
  investigation_evidence(id, title, location, description, added_by, created_at)`;

/** One page of investigations matching the text search and filters, plus the total match count. */
export async function findInvestigations(
  supabase: AuthClient,
  query: InvestigationListQuery,
  actorId: string,
): Promise<{ rows: InvestigationListItem[]; total: number }> {
  const { from, to } = toRange(query);

  const build = () => {
    let request = supabase
      .rpc("search_investigations", { p_query: query.q, p_tag: query.tag }, { count: "exact" })
      .select(LIST_SELECT);
    if (query.status) request = request.eq("status", query.status);
    if (query.priority) request = request.eq("priority", query.priority);
    if (query.origin) request = request.eq("origin", query.origin);
    if (query.analyst === ASSIGNEE_NONE) request = request.is("analyst_id", null);
    else if (query.analyst === ASSIGNEE_ME) request = request.eq("analyst_id", actorId);
    else if (query.analyst) request = request.eq("analyst_id", query.analyst);
    return request;
  };

  const { data, error, count } = await build()
    .order(query.sort, { ascending: query.order === "asc" })
    .order("id", { ascending: true }) // a stable tie-breaker keeps pages from overlapping
    .range(from, to);

  if (error?.code === "PGRST103") {
    // A page past the last row (a stale link, a hand-typed page number): learn the total, return no rows.
    const first = await build().range(0, 0);
    if (first.error) throw toApiError(first.error);
    return { rows: [], total: first.count ?? 0 };
  }
  if (error) throw toApiError(error);

  const rows = (data ?? []).map(
    ({ investigation_tags, investigation_indicators, investigation_alerts, ...row }) => ({
      ...row,
      tags: investigation_tags
        .flatMap((link) => (link.tags ? [link.tags] : []))
        .sort((a, b) => a.name.localeCompare(b.name)),
      indicator_count: investigation_indicators[0]?.count ?? 0,
      alert_count: investigation_alerts[0]?.count ?? 0,
    }),
  );
  return { rows, total: count ?? 0 };
}

/** The plain investigation row, for deciding what an update may do. */
export async function findInvestigationRow(
  supabase: AuthClient,
  id: string,
): Promise<Investigation | null> {
  const { data, error } = await supabase
    .from("investigations")
    .select("*")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** One investigation with everything attached to it, and its timeline. */
export async function findInvestigationDetail(
  supabase: AuthClient,
  id: string,
): Promise<InvestigationDetail | null> {
  const { data, error } = await supabase
    .from("investigations")
    .select(DETAIL_SELECT)
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const names = await findDisplayNames(supabase, [
    data.created_by,
    ...data.investigation_notes.map((note) => note.author_id),
    ...data.investigation_evidence.map((item) => item.added_by),
    ...data.investigation_indicators.map((link) => link.added_by),
    ...data.investigation_alerts.map((link) => link.added_by),
  ]);
  const nameOf = (userId: string | null) => (userId ? (names.get(userId) ?? null) : null);

  const notes: InvestigationNote[] = data.investigation_notes
    .map((note) => ({
      id: note.id,
      kind: note.kind === "system" ? ("system" as const) : ("note" as const),
      body: note.body,
      author_id: note.author_id,
      author_name: nameOf(note.author_id),
      created_at: note.created_at,
      updated_at: note.updated_at,
    }))
    .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));

  const evidence = data.investigation_evidence
    .map((item) => ({
      id: item.id,
      title: item.title,
      location: item.location,
      description: item.description,
      added_by_name: nameOf(item.added_by),
      created_at: item.created_at,
    }))
    .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));

  const indicators = data.investigation_indicators
    .flatMap((link) =>
      link.indicators
        ? [{ ...link.indicators, added_at: link.added_at, added_by_name: nameOf(link.added_by) }]
        : [],
    )
    .sort((a, b) => Date.parse(a.added_at) - Date.parse(b.added_at));

  const alerts = data.investigation_alerts
    .flatMap((link) =>
      link.alerts
        ? [{ ...link.alerts, added_at: link.added_at, added_by_name: nameOf(link.added_by) }]
        : [],
    )
    .sort((a, b) => Date.parse(a.added_at) - Date.parse(b.added_at));

  const {
    investigation_tags,
    investigation_notes: _notes,
    investigation_evidence: _evidence,
    investigation_indicators: _indicators,
    investigation_alerts: _alerts,
    ...row
  } = data;
  void [_notes, _evidence, _indicators, _alerts];

  const created_by_name = nameOf(data.created_by);
  return {
    ...row,
    created_by_name,
    tags: investigation_tags
      .flatMap((link) => (link.tags ? [link.tags] : []))
      .sort((a, b) => a.name.localeCompare(b.name)),
    indicators,
    alerts,
    notes,
    evidence,
    timeline: buildInvestigationTimeline({
      created_at: data.created_at,
      created_by_name,
      notes,
      evidence,
      indicators,
      alerts,
    }),
  };
}

export async function findInvestigationStats(supabase: AuthClient): Promise<InvestigationStats> {
  const { data, error } = await supabase.rpc("investigation_status_counts");
  if (error) throw toApiError(error);

  const counts = new Map(data.map((row) => [row.status, Number(row.total)]));
  const by_status = INVESTIGATION_STATUSES.map((status) => ({
    status,
    total: counts.get(status) ?? 0,
  }));
  return { total: by_status.reduce((sum, row) => sum + row.total, 0), by_status };
}

export async function insertInvestigation(
  supabase: AuthClient,
  input: {
    title: string;
    description?: string | null;
    priority?: Investigation["priority"];
    analyst_id: string | null;
  },
): Promise<Investigation> {
  const { data, error } = await supabase.from("investigations").insert(input).select("*").single();
  if (error) throw toApiError(error);
  return data;
}

export async function updateInvestigationRow(
  supabase: AuthClient,
  id: string,
  patch: Partial<
    Pick<
      Investigation,
      "title" | "description" | "status" | "priority" | "analyst_id" | "closed_at"
    >
  >,
): Promise<Investigation | null> {
  // With nothing to change but tags, just read the row (an empty UPDATE is a no-op for PostgREST).
  if (Object.keys(patch).length === 0) return findInvestigationRow(supabase, id);
  const { data, error } = await supabase
    .from("investigations")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function deleteInvestigationRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Investigation, "id" | "title" | "origin"> | null> {
  const { data, error } = await supabase
    .from("investigations")
    .delete()
    .eq("id", id)
    .select("id, title, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Replaces the tag set atomically (creating unknown tags) through set_investigation_tags(). */
export async function replaceInvestigationTags(
  supabase: AuthClient,
  id: string,
  tags: string[],
): Promise<void> {
  const { error } = await supabase.rpc("set_investigation_tags", {
    p_investigation_id: id,
    p_tags: tags,
  });
  if (error) {
    if (error.code === "23514") {
      throw apiErrors.validation({
        issues: [
          { path: "tags", message: "Check the tags: at most 20, up to 50 characters each." },
        ],
      });
    }
    throw toApiError(error);
  }
}

// --- indicators and alerts attached to an investigation -----------------------------------------------

function linkError(error: { code?: string; message: string }, what: "indicator" | "alert") {
  if (error.code === "23505") return apiErrors.conflict(`That ${what} is already attached.`);
  if (error.code === "23503") {
    return apiErrors.validation({
      issues: [{ path: `${what}_id`, message: `That ${what} does not exist.` }],
    });
  }
  return toApiError(error);
}

export async function insertIndicatorLinks(
  supabase: AuthClient,
  investigationId: string,
  indicatorIds: string[],
): Promise<void> {
  if (indicatorIds.length === 0) return;
  const { error } = await supabase
    .from("investigation_indicators")
    .insert(
      indicatorIds.map((indicator_id) => ({ investigation_id: investigationId, indicator_id })),
    );
  if (error) throw linkError(error, "indicator");
}

export async function insertAlertLinks(
  supabase: AuthClient,
  investigationId: string,
  alertIds: string[],
): Promise<void> {
  if (alertIds.length === 0) return;
  const { error } = await supabase
    .from("investigation_alerts")
    .insert(alertIds.map((alert_id) => ({ investigation_id: investigationId, alert_id })));
  if (error) throw linkError(error, "alert");
}

export async function deleteIndicatorLink(
  supabase: AuthClient,
  investigationId: string,
  indicatorId: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_indicators")
    .delete()
    .eq("investigation_id", investigationId)
    .eq("indicator_id", indicatorId)
    .select("indicator_id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

export async function deleteAlertLink(
  supabase: AuthClient,
  investigationId: string,
  alertId: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_alerts")
    .delete()
    .eq("investigation_id", investigationId)
    .eq("alert_id", alertId)
    .select("alert_id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

/** The value of an indicator or the title of an alert, for the audit trail. */
export async function findLinkLabel(
  supabase: AuthClient,
  kind: "indicator" | "alert",
  id: string,
): Promise<string | null> {
  if (kind === "indicator") {
    const { data } = await supabase.from("indicators").select("value").eq("id", id).maybeSingle();
    return data?.value ?? null;
  }
  const { data } = await supabase.from("alerts").select("title").eq("id", id).maybeSingle();
  return data?.title ?? null;
}

// --- notes -------------------------------------------------------------------------------------------

export async function findNote(
  supabase: AuthClient,
  investigationId: string,
  noteId: string,
): Promise<{ id: string; author_id: string | null; kind: string } | null> {
  const { data, error } = await supabase
    .from("investigation_notes")
    .select("id, author_id, kind")
    .eq("id", noteId)
    .eq("investigation_id", investigationId)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function insertNote(
  supabase: AuthClient,
  investigationId: string,
  body: string,
): Promise<{ id: string }> {
  const { data, error } = await supabase
    .from("investigation_notes")
    .insert({ investigation_id: investigationId, body })
    .select("id")
    .single();
  if (error) throw toApiError(error);
  return data;
}

export async function updateNoteRow(
  supabase: AuthClient,
  noteId: string,
  body: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_notes")
    .update({ body })
    .eq("id", noteId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

export async function deleteNoteRow(supabase: AuthClient, noteId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_notes")
    .delete()
    .eq("id", noteId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

/** Records a line of status history. Service role only: call it after authorizing the acting user. */
export async function insertSystemNote(
  investigationId: string,
  authorId: string,
  body: string,
): Promise<void> {
  const { error } = await createAdminClient()
    .from("investigation_notes")
    .insert({ investigation_id: investigationId, author_id: authorId, kind: "system", body });
  if (error) throw toApiError(error);
}

// --- evidence ---------------------------------------------------------------------------------------------

export async function insertEvidence(
  supabase: AuthClient,
  investigationId: string,
  input: EvidenceInput,
): Promise<{ id: string }> {
  const { data, error } = await supabase
    .from("investigation_evidence")
    .insert({ investigation_id: investigationId, ...input })
    .select("id")
    .single();
  if (error) throw toApiError(error);
  return data;
}

export async function deleteEvidenceRow(
  supabase: AuthClient,
  investigationId: string,
  evidenceId: string,
): Promise<{ title: string } | null> {
  const { data, error } = await supabase
    .from("investigation_evidence")
    .delete()
    .eq("id", evidenceId)
    .eq("investigation_id", investigationId)
    .select("title")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

// --- checklist ---------------------------------------------------------------------------------------------

type ChecklistRow = {
  id: string;
  text: string;
  done: boolean;
  source: string;
  created_by: string | null;
  created_at: string;
  done_by: string | null;
  done_at: string | null;
};

async function toChecklistItems(supabase: AuthClient, rows: ChecklistRow[]) {
  const names = await findDisplayNames(supabase, [
    ...rows.map((row) => row.created_by),
    ...rows.map((row) => row.done_by),
  ]);
  const nameOf = (userId: string | null) => (userId ? (names.get(userId) ?? null) : null);
  return rows.map((row) => ({
    id: row.id,
    text: row.text,
    done: row.done,
    source: row.source === "ai" ? ("ai" as const) : ("analyst" as const),
    created_by_name: nameOf(row.created_by),
    created_at: row.created_at,
    done_by_name: nameOf(row.done_by),
    done_at: row.done_at,
  }));
}

export async function findChecklistItems(supabase: AuthClient, investigationId: string) {
  const { data, error } = await supabase
    .from("investigation_checklist_items")
    .select("id, text, done, source, created_by, created_at, done_by, done_at")
    .eq("investigation_id", investigationId)
    .order("created_at", { ascending: true });
  if (error) throw toApiError(error);
  return toChecklistItems(supabase, data);
}

export async function insertChecklistItem(
  supabase: AuthClient,
  investigationId: string,
  text: string,
  source: "ai" | "analyst",
): Promise<void> {
  const { error } = await supabase
    .from("investigation_checklist_items")
    .insert({ investigation_id: investigationId, text, source });
  if (error) throw toApiError(error);
}

/** Seeds several items at once (an AI checklist suggestion becoming trackable rows). */
export async function insertChecklistItems(
  supabase: AuthClient,
  investigationId: string,
  texts: string[],
): Promise<void> {
  if (texts.length === 0) return;
  const { error } = await supabase
    .from("investigation_checklist_items")
    .insert(texts.map((text) => ({ investigation_id: investigationId, text, source: "ai" })));
  if (error) throw toApiError(error);
}

export async function updateChecklistItemRow(
  supabase: AuthClient,
  itemId: string,
  patch: { done: boolean; done_by: string | null; done_at: string | null },
): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_checklist_items")
    .update(patch)
    .eq("id", itemId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}

export async function deleteChecklistItemRow(
  supabase: AuthClient,
  investigationId: string,
  itemId: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("investigation_checklist_items")
    .delete()
    .eq("id", itemId)
    .eq("investigation_id", investigationId)
    .select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}
