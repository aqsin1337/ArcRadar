import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import type { BacktestBatch } from "./backtest";
import type { SiemId } from "./constants";
import type { BacktestSample } from "./types";

/*
 * Reads use the caller's own client (row level security: administrators only). The one write goes through
 * sync_rule_backtests() with the service role, after the request's API key has been verified.
 */

export type BacktestRow = {
  rule_key: string;
  window_hours: number;
  kind: string;
  matches: number;
  scanned: number | null;
  sample: BacktestSample[];
  search_sha256: string;
  error: string | null;
  reported_at: string;
};

export async function storeBacktests(
  siem: SiemId,
  results: BacktestBatch["results"],
): Promise<{ results: number }> {
  const { data, error } = await createAdminClient().rpc("sync_rule_backtests", {
    p_siem: siem,
    p_results: results as unknown as Json,
  });
  if (error) {
    if (["22023", "23514", "22P02", "22001", "23502"].includes(error.code)) {
      throw apiErrors.validation(undefined, "The report was refused: a value cannot be stored.");
    }
    throw toApiError(error);
  }
  return data as unknown as { results: number };
}

/** The backtests of the given rules, newest information included. */
export async function findBacktests(
  supabase: AuthClient,
  siem: SiemId,
  ruleKeys: string[],
): Promise<BacktestRow[]> {
  if (ruleKeys.length === 0) return [];
  const { data, error } = await supabase
    .from("siem_rule_backtests")
    .select(
      "rule_key, window_hours, kind, matches, scanned, sample, search_sha256, error, reported_at",
    )
    .eq("siem", siem)
    .in("rule_key", ruleKeys);
  if (error) throw toApiError(error);
  return data.map((row) => ({ ...row, sample: row.sample as unknown as BacktestSample[] }));
}
