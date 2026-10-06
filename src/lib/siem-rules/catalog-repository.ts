import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import type { CatalogBatch, CatalogSource, FieldCatalog } from "./catalog";
import type { SiemId } from "./constants";

/*
 * Reads use the caller's own client (row level security: administrators only). The one write goes
 * through sync_field_catalog() with the service role, after the request's API key has been verified.
 */

/** Replaces the catalog of every source in the batch, in one transaction. */
export async function storeCatalog(
  siem: SiemId,
  sources: CatalogBatch["sources"],
): Promise<{ sources: number; fields: number }> {
  const { data, error } = await createAdminClient().rpc("sync_field_catalog", {
    p_siem: siem,
    p_sources: sources as unknown as Json,
  });
  if (error) {
    if (["22023", "23514", "22P02", "22001", "23502"].includes(error.code)) {
      throw apiErrors.validation(undefined, "The report was refused: a value cannot be stored.");
    }
    throw toApiError(error);
  }
  return data as unknown as { sources: number; fields: number };
}

/** Every reported field of one SIEM, grouped by source, most common fields first. */
export async function findCatalog(
  supabase: AuthClient,
  siem: SiemId,
  options: { index?: string; sourcetype?: string } = {},
): Promise<FieldCatalog> {
  let query = supabase
    .from("siem_field_catalog")
    .select(
      "index_name, sourcetype, field, events_with_field, events_sampled, distinct_values, sample_values, window_hours, reported_at",
    )
    .eq("siem", siem)
    .order("events_with_field", { ascending: false })
    .limit(5000);
  if (options.index) query = query.eq("index_name", options.index);
  if (options.sourcetype) query = query.eq("sourcetype", options.sourcetype);
  const { data, error } = await query;
  if (error) throw toApiError(error);

  const bySource = new Map<string, CatalogSource>();
  for (const row of data) {
    const key = `${row.index_name}\u0000${row.sourcetype}`;
    let source = bySource.get(key);
    if (!source) {
      source = {
        index: row.index_name,
        sourcetype: row.sourcetype,
        events_sampled: row.events_sampled,
        window_hours: row.window_hours,
        reported_at: row.reported_at,
        fields: [],
      };
      bySource.set(key, source);
    }
    source.fields.push({
      name: row.field,
      events_with_field: row.events_with_field,
      distinct_values: row.distinct_values,
      sample_values: row.sample_values,
    });
  }
  const sources = [...bySource.values()].sort(
    (a, b) => b.events_sampled - a.events_sampled || a.index.localeCompare(b.index),
  );
  return { sources };
}
