import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findDisplayNames } from "@/lib/team/repository";
import type { CreateDetectionRuleInput, UpdateDetectionRuleInput } from "./schema";
import type { DetectionRule, DetectionRuleCondition } from "./types";

/*
 * All queries use the caller's own client, so row level security is the final authority on what is
 * visible and writable.
 */

type Row = {
  id: number;
  name: string;
  description: string | null;
  // jsonb, not a Postgres enum: PostgREST hands it back typed only as far as the generator can tell.
  conditions: unknown;
  severity: DetectionRule["severity"];
  priority: number;
  enabled: boolean;
  origin: DetectionRule["origin"];
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

async function toRules(supabase: AuthClient, rows: Row[]): Promise<DetectionRule[]> {
  const names = await findDisplayNames(
    supabase,
    rows.map((row) => row.created_by),
  );
  return rows.map(({ created_by, conditions, ...row }) => ({
    ...row,
    conditions: conditions as DetectionRuleCondition[],
    created_by_name: created_by ? (names.get(created_by) ?? null) : null,
  }));
}

export async function findDetectionRules(supabase: AuthClient): Promise<DetectionRule[]> {
  const { data, error } = await supabase
    .from("detection_rules")
    .select("*")
    .order("priority")
    .order("id");
  if (error) throw toApiError(error);
  return toRules(supabase, data);
}

export async function insertDetectionRule(
  supabase: AuthClient,
  input: CreateDetectionRuleInput,
): Promise<DetectionRule> {
  const { data, error } = await supabase.from("detection_rules").insert(input).select("*").single();
  if (error) {
    if (error.code === "23505") {
      throw apiErrors.conflict("A detection rule with this id already exists.");
    }
    throw toApiError(error);
  }
  const [row] = await toRules(supabase, [data]);
  return row;
}

export async function updateDetectionRuleRow(
  supabase: AuthClient,
  id: number,
  patch: UpdateDetectionRuleInput,
): Promise<DetectionRule | null> {
  const { data, error } = await supabase
    .from("detection_rules")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;
  const [row] = await toRules(supabase, [data]);
  return row;
}

export async function deleteDetectionRuleRow(
  supabase: AuthClient,
  id: number,
): Promise<{ id: number; name: string } | null> {
  const { data, error } = await supabase
    .from("detection_rules")
    .delete()
    .eq("id", id)
    .select("id, name")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}
