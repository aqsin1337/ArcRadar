import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findDisplayNames } from "@/lib/team/repository";
import type { Database, Json } from "@/types/database";
import { expectedSearchDigest } from "./backtest";
import { findBacktests } from "./backtest-repository";
import { RULE_KEY_FIRST, type SiemId } from "./constants";
import { getDialect } from "./dialects";
import type { SiemRule } from "./types";

/* Every query uses the caller's own client: row level security decides who sees or writes a rule. */

type JsonObject = { [key: string]: Json | undefined };
type Row = Database["public"]["Tables"]["siem_rules"]["Row"];
type Insert = Database["public"]["Tables"]["siem_rules"]["Insert"];
type Update = Database["public"]["Tables"]["siem_rules"]["Update"];

async function toRules(supabase: AuthClient, rows: Row[]): Promise<SiemRule[]> {
  const names = await findDisplayNames(
    supabase,
    rows.map((row) => row.created_by),
  );
  // Every caller passes the rules of one SIEM.
  const backtests = await findBacktests(
    supabase,
    (rows[0]?.siem ?? "splunk") as SiemId,
    rows.map((row) => row.rule_key),
  );
  return rows.map(({ created_by, spec, ...row }) => {
    const rule = {
      ...row,
      siem: row.siem as SiemRule["siem"],
      severity: row.severity as SiemRule["severity"],
      mode: row.mode as SiemRule["mode"],
      status: row.status as SiemRule["status"],
      source: row.source as SiemRule["source"],
      spec: spec as Record<string, unknown>,
      created_by_name: created_by ? (names.get(created_by) ?? null) : null,
    };
    const file = getDialect(rule.siem).render(rule);
    const expected = expectedSearchDigest(file.content);
    return {
      ...rule,
      file,
      backtests: backtests
        .filter((backtest) => backtest.rule_key === rule.rule_key)
        .sort((a, b) => a.window_hours - b.window_hours)
        .map((backtest) => ({
          window_hours: backtest.window_hours as 24 | 168,
          kind: backtest.kind as "threshold" | "events",
          matches: backtest.matches,
          scanned: backtest.scanned,
          sample: backtest.sample,
          error: backtest.error,
          reported_at: backtest.reported_at,
          stale: backtest.search_sha256 !== expected,
        })),
    };
  });
}

export async function findSiemRules(supabase: AuthClient, siem: SiemId): Promise<SiemRule[]> {
  const { data, error } = await supabase
    .from("siem_rules")
    .select("*")
    .eq("siem", siem)
    .order("created_at", { ascending: false });
  if (error) throw toApiError(error);
  return toRules(supabase, data);
}

export async function findSiemRule(
  supabase: AuthClient,
  siem: SiemId,
  id: string,
): Promise<SiemRule | null> {
  const { data, error } = await supabase
    .from("siem_rules")
    .select("*")
    .eq("siem", siem)
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

/** The next unused numeric key (counting up from the floor); keys that are not numbers are ignored. */
export async function nextRuleKey(supabase: AuthClient, siem: SiemId): Promise<string> {
  const { data, error } = await supabase.from("siem_rules").select("rule_key").eq("siem", siem);
  if (error) throw toApiError(error);
  const numbers = data.map((row) => (/^[0-9]{1,9}$/.test(row.rule_key) ? Number(row.rule_key) : 0));
  return String(Math.max(Math.max(0, ...numbers) + 1, RULE_KEY_FIRST));
}

export async function insertSiemRule(
  supabase: AuthClient,
  input: Omit<Insert, "spec"> & { spec: Record<string, unknown> },
): Promise<SiemRule> {
  const { data, error } = await supabase
    .from("siem_rules")
    .insert({ ...input, spec: input.spec as JsonObject })
    .select("*")
    .single();
  if (error) {
    if (error.code === "23505") throw apiErrors.conflict("A rule with this key already exists.");
    throw toApiError(error);
  }
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

export async function updateSiemRuleRow(
  supabase: AuthClient,
  siem: SiemId,
  id: string,
  patch: Omit<Update, "spec"> & { spec?: Record<string, unknown> },
): Promise<SiemRule | null> {
  const { spec, ...rest } = patch;
  const { data, error } = await supabase
    .from("siem_rules")
    .update(spec === undefined ? rest : { ...rest, spec: spec as JsonObject })
    .eq("siem", siem)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

export async function deleteSiemRuleRow(
  supabase: AuthClient,
  siem: SiemId,
  id: string,
): Promise<{ id: string; name: string } | null> {
  const { data, error } = await supabase
    .from("siem_rules")
    .delete()
    .eq("siem", siem)
    .eq("id", id)
    .select("id, name")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}
