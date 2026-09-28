import "server-only";
import { fetchPage } from "@/lib/api/fetch-page";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import type { Json } from "@/types/database";
import type { Report, ReportType } from "@/types/domain";
import type { ReportListQuery } from "./schema";

/** search_reports() answers the title question; the type filter is ordinary PostgREST. */
export async function findReports(
  supabase: AuthClient,
  query: ReportListQuery,
): Promise<{ rows: Report[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase
      .rpc("search_reports", { p_query: query.q }, { count: "exact" })
      .select("*");
    if (query.type) request = request.eq("type", query.type);
    return request;
  };

  return fetchPage<Report>(
    () =>
      build()
        .order("created_at", { ascending: false })
        .order("id", { ascending: false })
        .range(from, to),
    () => build().range(0, 0),
  );
}

export async function findReport(supabase: AuthClient, id: string): Promise<Report | null> {
  const { data, error } = await supabase.from("reports").select("*").eq("id", id).maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function insertReport(
  supabase: AuthClient,
  input: {
    title: string;
    type: ReportType;
    investigation_id: string | null;
    parameters: NonNullable<Json>;
    content: NonNullable<Json>;
  },
): Promise<Report> {
  const { data, error } = await supabase
    .from("reports")
    .insert({
      title: input.title,
      type: input.type,
      investigation_id: input.investigation_id,
      parameters: input.parameters,
      content: input.content,
    })
    .select("*")
    .single();
  if (error) throw toApiError(error);
  return data;
}

/** True when a row existed and was removed. */
export async function deleteReportRow(supabase: AuthClient, id: string): Promise<boolean> {
  const { data, error } = await supabase.from("reports").delete().eq("id", id).select("id");
  if (error) throw toApiError(error);
  return data.length > 0;
}
