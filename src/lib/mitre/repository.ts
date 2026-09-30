import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import type { Alert } from "@/types/domain";
import type { CatalogTechnique, ObservedRow } from "./types";

/*
 * Everything here reads with the caller's own client, so row level security decides what is visible:
 * the technique catalog needs threat_intel:read, and what was "observed" is computed from the alerts
 * the caller may read.
 */

/** The whole technique catalog (parents and sub-techniques), lightweight. */
export async function findCatalog(supabase: AuthClient): Promise<CatalogTechnique[]> {
  const { data, error } = await supabase
    .from("mitre_techniques")
    .select("id, name, tactics, url")
    .order("id")
    .limit(2000);
  if (error) throw toApiError(error);
  return data;
}

export async function findObserved(supabase: AuthClient): Promise<ObservedRow[]> {
  const { data, error } = await supabase.rpc("mitre_observed_techniques");
  if (error) throw toApiError(error);
  return data.map((row) => ({
    technique_id: row.technique_id,
    alert_count: Number(row.alert_count),
    max_severity: row.max_severity,
    last_seen: row.last_seen,
  }));
}

export async function findTechnique(
  supabase: AuthClient,
  id: string,
): Promise<(CatalogTechnique & { description: string | null }) | null> {
  const { data, error } = await supabase
    .from("mitre_techniques")
    .select("id, name, tactics, url, description")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** The sub-techniques of a parent technique (empty for a sub-technique). */
export async function findSubtechniques(
  supabase: AuthClient,
  parentId: string,
): Promise<{ id: string; name: string }[]> {
  const { data, error } = await supabase
    .from("mitre_techniques")
    .select("id, name")
    .like("id", `${parentId}.%`)
    .order("id");
  if (error) throw toApiError(error);
  return data;
}

/** The newest alerts that name any of the given technique ids, and how many there are in all. */
export async function findAlertsForTechniques(
  supabase: AuthClient,
  ids: readonly string[],
  limit: number,
): Promise<{ alerts: Alert[]; total: number }> {
  const { data, error, count } = await supabase
    .from("alerts")
    .select("*", { count: "exact" })
    .is("duplicate_of", null)
    .overlaps("technique_ids", [...ids])
    .order("created_at", { ascending: false })
    .limit(limit);
  if (error) throw toApiError(error);
  return { alerts: data, total: count ?? data.length };
}

/** Text search over id, name, description and tactics (all words must match), newest ids first. */
export async function searchTechniques(
  supabase: AuthClient,
  text: string,
  limit: number,
): Promise<{ rows: CatalogTechnique[]; total: number }> {
  const { data, error, count } = await supabase
    .rpc("search_mitre_techniques", { p_query: text }, { count: "exact" })
    .select("id, name, tactics, url")
    .order("id")
    .limit(limit);
  if (error) throw toApiError(error);
  return { rows: data ?? [], total: count ?? 0 };
}
