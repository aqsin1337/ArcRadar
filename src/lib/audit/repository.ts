import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { Database } from "@/types/database";
import type { AuditLogEntry } from "@/types/domain";
import type { AuditLogQuery } from "./query";

/**
 * Reads audit_logs with the caller's own client, so RLS (`audit:read`) is the final authority even
 * if a route guard were ever removed.
 */
export async function findAuditLogs(
  supabase: SupabaseClient<Database>,
  query: AuditLogQuery,
): Promise<{ rows: AuditLogEntry[]; total: number }> {
  const { from, to } = toRange(query);

  let request = supabase.from("audit_logs").select("*", { count: "exact" });
  if (query.action) request = request.eq("action", query.action);
  if (query.user_id) request = request.eq("user_id", query.user_id);
  if (query.entity_type) request = request.eq("entity_type", query.entity_type);
  if (query.entity_id) request = request.eq("entity_id", query.entity_id);
  if (query.from) request = request.gte("created_at", query.from);
  if (query.to) request = request.lte("created_at", query.to);

  const { data, error, count } = await request
    .order("created_at", { ascending: false })
    .order("id", { ascending: false })
    .range(from, to);
  if (error) throw toApiError(error);

  return { rows: data, total: count ?? 0 };
}
