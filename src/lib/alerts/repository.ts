import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { techniqueFilterIds } from "@/lib/mitre/service";
import type { Alert, AlertStatus } from "@/types/domain";
import { ASSIGNEE_ME, ASSIGNEE_NONE } from "./constants";
import type { AlertListQuery, CreateAlertInput } from "./schema";
import type { AlertDetail, AlertDuplicate, AlertListItem, AlertStats } from "./types";
import { ALERT_STATUSES } from "./constants";

/*
 * All queries use the caller's own client, so row level security is the final authority on what is
 * visible and writable, whatever the route guard decided.
 */

const LIST_SELECT =
  "*, indicator:indicators(id, type, value), assignee:profiles!assigned_to(id, display_name), asset:assets(id, name)";

const DETAIL_SELECT = `*,
  indicator:indicators(id, type, value, verdict, severity),
  assignee:profiles!assigned_to(id, display_name),
  asset:assets(id, name, ip_address, os),
  event:events(id, title, event_type, severity, source, occurred_at, payload),
  matched_rule:detection_rules!matched_rule_id(id, name),
  investigation_alerts(added_at, investigations(id, title, status, priority))`;

/** One page of alerts matching the text search and filters, plus the total match count. */
export async function findAlerts(
  supabase: AuthClient,
  query: AlertListQuery,
  actorId: string,
): Promise<{ rows: AlertListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const techniqueIds = query.technique ? await techniqueFilterIds(supabase, query.technique) : null;

  // search_alerts() answers the text question; everything else is ordinary PostgREST.
  const build = () => {
    let request = supabase
      .rpc("search_alerts", { p_query: query.q }, { count: "exact" })
      .select(LIST_SELECT);
    if (query.status) request = request.eq("status", query.status);
    if (query.severity) request = request.eq("severity", query.severity);
    if (query.origin) request = request.eq("origin", query.origin);
    if (query.source) request = request.eq("source", query.source);
    if (query.assignee === ASSIGNEE_NONE) request = request.is("assigned_to", null);
    else if (query.assignee === ASSIGNEE_ME) request = request.eq("assigned_to", actorId);
    else if (query.assignee) request = request.eq("assigned_to", query.assignee);
    // A duplicate is linked to its primary instead of sitting as a fresh row in the queue; showing it
    // is an explicit opt-in (query.duplicates === "show"), never the default view.
    if (query.duplicates !== "show") request = request.is("duplicate_of", null);
    if (techniqueIds) request = request.overlaps("technique_ids", techniqueIds);
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

  return { rows: data ?? [], total: count ?? 0 };
}

export async function findAlertDetail(
  supabase: AuthClient,
  id: string,
): Promise<AlertDetail | null> {
  const { data, error } = await supabase
    .from("alerts")
    .select(DETAIL_SELECT)
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  let createdByName: string | null = null;
  if (data.created_by) {
    const author = await supabase
      .from("profiles")
      .select("display_name")
      .eq("id", data.created_by)
      .maybeSingle();
    createdByName = author.data?.display_name ?? null;
  }

  // Techniques a sensor tagged the alert with; the ones the workspace knows get a name (and a link).
  const known = new Map<string, string>();
  if (data.technique_ids.length > 0) {
    const found = await supabase
      .from("mitre_techniques")
      .select("id, name")
      .in("id", data.technique_ids);
    if (found.error) throw toApiError(found.error);
    for (const technique of found.data) known.set(technique.id, technique.name);
  }

  // A primary alert with duplicates lists them; a duplicate itself never has any (see the check
  // constraint alerts_duplicate_count_only_primary), so this is skipped for one.
  let duplicates: AlertDuplicate[] = [];
  if (data.duplicate_count > 0) {
    const dup = await supabase
      .from("alerts")
      .select("id, title, severity, status, created_at")
      .eq("duplicate_of", id)
      .order("created_at", { ascending: false });
    if (dup.error) throw toApiError(dup.error);
    duplicates = dup.data;
  }

  // A duplicate names its primary. This is a plain, explicit query, not a `table!column` embed:
  // PostgREST cannot tell a self-referencing table's forward direction ("the row I point to") from
  // its reverse ("the rows that point to me") just from the column hint, and resolved it as the
  // latter here -- the same ambiguity the `duplicates` query above sidesteps the same way.
  let primaryAlert: AlertDetail["primary_alert"] = null;
  if (data.duplicate_of) {
    const primary = await supabase
      .from("alerts")
      .select("id, title, severity, status")
      .eq("id", data.duplicate_of)
      .maybeSingle();
    if (primary.error) throw toApiError(primary.error);
    primaryAlert = primary.data;
  }

  const { investigation_alerts, ...row } = data;
  return {
    ...row,
    primary_alert: primaryAlert,
    techniques: data.technique_ids.map((id) => ({ id, name: known.get(id) ?? null })),
    created_by_name: createdByName,
    duplicates,
    investigations: investigation_alerts
      .flatMap((link) =>
        link.investigations ? [{ ...link.investigations, added_at: link.added_at }] : [],
      )
      .sort((a, b) => Date.parse(b.added_at) - Date.parse(a.added_at)),
  };
}

/** The plain alert row, for deciding what an update may do. */
export async function findAlertRow(supabase: AuthClient, id: string): Promise<Alert | null> {
  const { data, error } = await supabase.from("alerts").select("*").eq("id", id).maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** How many alerts are in each status, and how many nobody has picked up. */
export async function findAlertStats(supabase: AuthClient): Promise<AlertStats> {
  const { data, error } = await supabase.rpc("alert_status_counts");
  if (error) throw toApiError(error);

  const counts = new Map(
    data.map((row) => [
      row.status,
      { total: Number(row.total), unassigned: Number(row.unassigned) },
    ]),
  );
  const by_status = ALERT_STATUSES.map((status) => ({
    status,
    total: counts.get(status)?.total ?? 0,
    unassigned: counts.get(status)?.unassigned ?? 0,
  }));
  return {
    total: by_status.reduce((sum, row) => sum + row.total, 0),
    unassigned: by_status.reduce((sum, row) => sum + row.unassigned, 0),
    by_status,
  };
}

export async function findAlertSources(supabase: AuthClient): Promise<string[]> {
  const { data, error } = await supabase.rpc("alert_sources");
  if (error) throw toApiError(error);
  return data;
}

/** Inserts a manual, local alert. `origin` and `created_by` come from the database. */
export async function insertAlert(supabase: AuthClient, input: CreateAlertInput): Promise<Alert> {
  const { data, error } = await supabase
    .from("alerts")
    .insert({ ...input, source: "manual" })
    .select("*")
    .single();
  if (error) {
    if (error.code === "23503") {
      throw apiErrors.validation({
        issues: [{ path: "indicator_id", message: "That indicator does not exist." }],
      });
    }
    throw toApiError(error);
  }
  return data;
}

/**
 * Updates an alert. With `expectedStatus` the update only applies while the alert is still in that
 * status, so two analysts acting on the same alert cannot silently overwrite each other; `null`
 * means the alert is gone or has changed.
 */
export async function updateAlertRow(
  supabase: AuthClient,
  id: string,
  patch: Partial<Pick<Alert, "status" | "acknowledged_at" | "resolved_at" | "assigned_to">>,
  expectedStatus?: AlertStatus,
): Promise<Alert | null> {
  let request = supabase.from("alerts").update(patch).eq("id", id);
  if (expectedStatus) request = request.eq("status", expectedStatus);
  const { data, error } = await request.select("*").maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function deleteAlertRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Alert, "id" | "title" | "origin"> | null> {
  const { data, error } = await supabase
    .from("alerts")
    .delete()
    .eq("id", id)
    .select("id, title, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}
