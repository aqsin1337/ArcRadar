import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { buildPage, type Page } from "@/lib/api/pagination";
import type { Database } from "@/types/database";
import type { AuditLogEntry } from "@/types/domain";
import type { AuditLogQuery } from "./query";
import { findAuditLogs } from "./repository";

export async function listAuditLogs(
  supabase: SupabaseClient<Database>,
  query: AuditLogQuery,
): Promise<Page<AuditLogEntry>> {
  const { rows, total } = await findAuditLogs(supabase, query);
  return buildPage(rows, total, query);
}
