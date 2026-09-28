import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { fetchPage } from "@/lib/api/fetch-page";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import type { AssetListQuery, EventListQuery } from "./schema";
import type {
  AssetListItem,
  EventListItem,
  IngestSummary,
  NormalizedRecord,
  SourceHealth,
} from "./types";

/*
 * Reads use the caller's own client, so row level security decides what is visible. The one write,
 * recording sensor data, goes through ingest_telemetry() with the service role, after the request's
 * API key has been verified.
 */

/**
 * Records a batch through the database function. It is one transaction and every record is
 * idempotent, so a retry changes nothing. A record the database cannot store fails the whole batch.
 */
export async function ingestRecords(
  source: string,
  records: NormalizedRecord[],
): Promise<IngestSummary> {
  const { data, error } = await createAdminClient().rpc("ingest_telemetry", {
    p_source: source,
    p_records: records as unknown as Json,
  });
  if (error) {
    if (["22023", "23514", "22P02", "22007", "22001", "23502"].includes(error.code)) {
      throw apiErrors.validation(
        undefined,
        "The batch was refused: a record has a value that cannot be stored.",
      );
    }
    throw toApiError(error);
  }
  return data as unknown as IngestSummary;
}

export async function findSourceHealth(supabase: AuthClient): Promise<SourceHealth[]> {
  const { data, error } = await supabase.rpc("telemetry_source_health");
  if (error) throw toApiError(error);
  return data.map((row) => ({
    ...row,
    events_total: Number(row.events_total),
    events_24h: Number(row.events_24h),
    alerts_total: Number(row.alerts_total),
    assets_total: Number(row.assets_total),
  }));
}

export async function findAssets(
  supabase: AuthClient,
  query: AssetListQuery,
): Promise<{ rows: AssetListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase.from("assets").select("*", { count: "exact" });
    if (query.source) request = request.eq("source", query.source);
    if (query.origin) request = request.eq("origin", query.origin);
    return request;
  };
  return fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc" })
        .order("id", { ascending: true })
        .range(from, to),
    () => build().range(0, 0),
  );
}

const EVENT_SELECT =
  "id, event_type, title, severity, source, origin, occurred_at, created_at, asset_id, indicator_id, asset:assets(id, name), alerts(id)";

export async function findEvents(
  supabase: AuthClient,
  query: EventListQuery,
): Promise<{ rows: EventListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase.from("events").select(EVENT_SELECT, { count: "exact" });
    if (query.source) request = request.eq("source", query.source);
    if (query.severity) request = request.eq("severity", query.severity);
    if (query.origin) request = request.eq("origin", query.origin);
    if (query.asset) request = request.eq("asset_id", query.asset);
    return request;
  };
  const { rows, total } = await fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc" })
        .order("id", { ascending: true })
        .range(from, to),
    () => build().range(0, 0),
  );
  return {
    rows: rows.map(({ alerts, ...row }) => ({ ...row, alert_id: alerts[0]?.id ?? null })),
    total,
  };
}
