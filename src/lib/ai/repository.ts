import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import type { Json } from "@/types/database";
import type { AiAnalysisKind, AiAnalysisRecord, AiProviderId, AiSubjectType } from "./types";

/** ai_analyses.kind and .subject_type are `text` + a check constraint, not a Postgres enum, so
 * PostgREST hands back a plain `string`; the check constraint is what actually guarantees one of the
 * known values, the same reasoning `investigations/repository.ts` applies to `notes.kind`. */
function narrowRow(row: {
  kind: string;
  subject_type: string;
  content: unknown;
  [key: string]: unknown;
}): AiAnalysisRecord {
  return {
    ...row,
    kind: row.kind as AiAnalysisKind,
    subject_type: row.subject_type as AiSubjectType,
  } as AiAnalysisRecord;
}

export type AiSettingsRow = {
  active_provider: string | null;
  active_model: string | null;
  updated_at: string;
};

export async function findAiSettings(supabase: AuthClient): Promise<AiSettingsRow | null> {
  const { data, error } = await supabase
    .from("ai_settings")
    .select("active_provider, active_model, updated_at")
    .eq("id", true)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function updateAiSettings(
  supabase: AuthClient,
  patch: { active_provider: AiProviderId | null; active_model: string | null; updated_by: string },
): Promise<AiSettingsRow | null> {
  const { data, error } = await supabase
    .from("ai_settings")
    .update(patch)
    .eq("id", true)
    .select("active_provider, active_model, updated_at")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export type AiAnalysisRow = AiAnalysisRecord;

export async function insertAiAnalysis(
  supabase: AuthClient,
  row: {
    kind: AiAnalysisKind;
    subject_type: AiSubjectType;
    subject_id: string;
    provider: string;
    model: string;
    prompt_version: number;
    content: unknown;
  },
): Promise<AiAnalysisRow> {
  const { data, error } = await supabase
    .from("ai_analyses")
    .insert({ ...row, content: row.content as NonNullable<Json> })
    .select("*")
    .single();
  if (error) throw toApiError(error);
  return narrowRow(data);
}

/** Every analysis for one subject, newest first — the service groups this into "latest per kind"
 * plus a small history. */
export async function findAiAnalyses(
  supabase: AuthClient,
  subjectType: AiSubjectType,
  subjectId: string,
): Promise<AiAnalysisRow[]> {
  const { data, error } = await supabase
    .from("ai_analyses")
    .select("*")
    .eq("subject_type", subjectType)
    .eq("subject_id", subjectId)
    .order("created_at", { ascending: false })
    .limit(50);
  if (error) throw toApiError(error);
  return data.map(narrowRow);
}

export async function updateAlertFalsePositiveScore(
  supabase: AuthClient,
  alertId: string,
  score: number,
): Promise<void> {
  const { error } = await supabase.from("alerts").update({ ai_fp_score: score }).eq("id", alertId);
  if (error) throw toApiError(error);
}
