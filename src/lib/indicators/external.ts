import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import type { IndicatorType, Severity, Verdict } from "@/types/domain";

/*
 * The one write path for indicators ArcRadar learned from an outside service (the answer of a live
 * lookup, an entry of a public threat feed). It calls record_external_indicators() with the service
 * role: rows are stored as origin 'external', an indicator somebody tracks as local or demo is never
 * changed, and a verdict only ever moves up. Callers authorize first; this module never decides who
 * may do what.
 */

export type ExternalIndicatorRecord = {
  type: IndicatorType;
  value: string;
  verdict: Verdict;
  severity: Severity;
  /** 0-100. */
  confidence: number;
  description?: string | null;
  /** When the source last saw it (ISO); defaults to now in the database. */
  seen_at?: string | null;
};

export type RecordSummary = {
  created: number;
  updated: number;
  /** Already tracked as local or demo: left exactly as it was. */
  untouched: number;
  /** A value the database refused. */
  skipped: number;
};

/** The database function's limit for one call. */
export const MAX_RECORDS_PER_CALL = 5000;

export const EMPTY_SUMMARY: RecordSummary = { created: 0, updated: 0, untouched: 0, skipped: 0 };

export function addSummaries(a: RecordSummary, b: RecordSummary): RecordSummary {
  return {
    created: a.created + b.created,
    updated: a.updated + b.updated,
    untouched: a.untouched + b.untouched,
    skipped: a.skipped + b.skipped,
  };
}

/** `source` is stored on the indicator and must match [a-z0-9_:.-]{1,60}. Splits large batches. */
export async function recordExternalIndicators(
  source: string,
  records: readonly ExternalIndicatorRecord[],
): Promise<RecordSummary> {
  let total = EMPTY_SUMMARY;
  const admin = createAdminClient();
  for (let i = 0; i < records.length; i += MAX_RECORDS_PER_CALL) {
    const chunk = records.slice(i, i + MAX_RECORDS_PER_CALL);
    const { data, error } = await admin.rpc("record_external_indicators", {
      p_source: source,
      p_records: chunk as unknown as Json,
    });
    if (error) {
      if (error.code === "22023") throw apiErrors.validation(undefined, error.message);
      throw toApiError(error);
    }
    total = addSummaries(total, data as unknown as RecordSummary);
  }
  return total;
}
