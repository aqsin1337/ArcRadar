import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findDisplayNames } from "@/lib/team/repository";
import type { Database } from "@/types/database";
import { WAZUH_RULE_ID_MIN } from "./constants";
import type { WazuhRule, WazuhRuleCondition } from "./types";
import { renderWazuhRuleXml } from "./xml";

/* Every query uses the caller's own client: row level security decides who sees or writes a rule. */

type Row = Database["public"]["Tables"]["wazuh_rules"]["Row"];
type Insert = Database["public"]["Tables"]["wazuh_rules"]["Insert"];
type Update = Database["public"]["Tables"]["wazuh_rules"]["Update"];

type Stats = Map<number, { triggers: number; last_triggered: string | null }>;

async function findStats(supabase: AuthClient): Promise<Stats> {
  const { data, error } = await supabase.rpc("wazuh_rule_trigger_stats");
  if (error) throw toApiError(error);
  return new Map(
    data.map((row) => [
      row.rule_id,
      { triggers: Number(row.triggers), last_triggered: row.last_triggered },
    ]),
  );
}

async function toRules(supabase: AuthClient, rows: Row[]): Promise<WazuhRule[]> {
  const [names, stats] = await Promise.all([
    findDisplayNames(
      supabase,
      rows.map((row) => row.created_by),
    ),
    findStats(supabase),
  ]);
  return rows.map(({ created_by, conditions, ...row }) => {
    const rule = {
      ...row,
      conditions: conditions as WazuhRuleCondition[],
      parent_kind: row.parent_kind as WazuhRule["parent_kind"],
      status: row.status as WazuhRule["status"],
      source: row.source as WazuhRule["source"],
      created_by_name: created_by ? (names.get(created_by) ?? null) : null,
      triggers: stats.get(row.id)?.triggers ?? 0,
      last_triggered: stats.get(row.id)?.last_triggered ?? null,
    };
    return { ...rule, xml: renderWazuhRuleXml(rule) };
  });
}

export async function findWazuhRules(supabase: AuthClient): Promise<WazuhRule[]> {
  const { data, error } = await supabase
    .from("wazuh_rules")
    .select("*")
    .order("id", { ascending: false });
  if (error) throw toApiError(error);
  return toRules(supabase, data);
}

export async function findWazuhRule(supabase: AuthClient, id: number): Promise<WazuhRule | null> {
  const { data, error } = await supabase.from("wazuh_rules").select("*").eq("id", id).maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

/** The next unused id above the reserved floor. */
export async function nextWazuhRuleId(supabase: AuthClient): Promise<number> {
  const { data, error } = await supabase
    .from("wazuh_rules")
    .select("id")
    .order("id", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw toApiError(error);
  return Math.max((data?.id ?? 0) + 1, WAZUH_RULE_ID_MIN);
}

export async function insertWazuhRule(supabase: AuthClient, input: Insert): Promise<WazuhRule> {
  const { data, error } = await supabase.from("wazuh_rules").insert(input).select("*").single();
  if (error) {
    if (error.code === "23505")
      throw apiErrors.conflict("A Wazuh rule with this id already exists.");
    throw toApiError(error);
  }
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

export async function updateWazuhRuleRow(
  supabase: AuthClient,
  id: number,
  patch: Update,
): Promise<WazuhRule | null> {
  const { data, error } = await supabase
    .from("wazuh_rules")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [rule] = await toRules(supabase, [data]);
  return rule;
}

export async function deleteWazuhRuleRow(
  supabase: AuthClient,
  id: number,
): Promise<{ id: number; name: string } | null> {
  const { data, error } = await supabase
    .from("wazuh_rules")
    .delete()
    .eq("id", id)
    .select("id, name")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}
