import type { z } from "zod";

/**
 * Types shared by the AI providers and the analysis service. Nothing here depends on a particular
 * provider: every adapter is asked for the same shape of answer and validated the same way, the same
 * relationship `src/lib/intel/types.ts` has with its providers.
 */

export const AI_ANALYSIS_KINDS = [
  "threat_summary",
  "attack_vector",
  "severity_validation",
  "response_actions",
  "false_positive_score",
  "investigation_checklist",
  "verdict_recommendation",
] as const;
export type AiAnalysisKind = (typeof AI_ANALYSIS_KINDS)[number];

/** What an analysis can attach to: alerts (Phase 8), investigations and indicators (Phase 9). */
export const AI_SUBJECT_TYPES = ["alert", "investigation", "indicator"] as const;
export type AiSubjectType = (typeof AI_SUBJECT_TYPES)[number];

/** Which subject type each kind belongs to (mirrors the database's own
 * `ai_analyses_kind_subject_match_check`, the authority; this is the fast application-side check). */
export const AI_KIND_SUBJECT_TYPE: Record<AiAnalysisKind, AiSubjectType> = {
  threat_summary: "alert",
  attack_vector: "alert",
  severity_validation: "alert",
  response_actions: "alert",
  false_positive_score: "alert",
  investigation_checklist: "investigation",
  verdict_recommendation: "indicator",
};

export const AI_PROVIDER_IDS = ["groq", "openai", "anthropic", "deepseek", "ollama"] as const;
export type AiProviderId = (typeof AI_PROVIDER_IDS)[number];

export type AiProviderInfo = { id: AiProviderId; name: string };

/** One AI-capable row of the integration catalog, as the settings API and the Integrations page's AI
 * picker see it. Kept here (not in `service.ts`, which is server-only) so a Client Component can
 * import the type without pulling in server code, the same split `src/lib/integrations/types.ts` has
 * from `integrations/service.ts`. */
export type AiProviderStatus = {
  id: AiProviderId;
  name: string;
  configured: boolean;
  enabled: boolean;
};

export type AiAvailability = {
  active_provider: AiProviderId | null;
  active_model: string | null;
  updated_at: string | null;
  providers: AiProviderStatus[];
  /** True once an active provider is chosen and is both configured and enabled right now. */
  ready: boolean;
};

/** One stored analysis, as the API and the alert page see it. `content` is validated JSON whose exact
 * shape depends on `kind` (see `src/lib/ai/schemas.ts`'s `AiAnalysisContent`). */
export type AiAnalysisRecord = {
  id: string;
  kind: AiAnalysisKind;
  subject_type: AiSubjectType;
  subject_id: string;
  provider: string;
  model: string;
  prompt_version: number;
  content: unknown;
  requested_by: string | null;
  created_at: string;
};

export type SubjectAnalyses = {
  latest: Partial<Record<AiAnalysisKind, AiAnalysisRecord>>;
  history: AiAnalysisRecord[];
};

export type AiCompleteRequest = {
  system: string;
  user: string;
  /** The JSON shape the caller needs back. The adapter asks the model for JSON; the service still
   * validates the answer against this schema before anything is stored or shown. */
  schema: z.ZodType;
  maxOutputTokens: number;
  signal: AbortSignal;
  /** Overrides the adapter's default model (from `ai_settings.active_model`), when an administrator
   * set one. */
  model?: string;
};

export type AiCompleteResult = {
  /** Parsed JSON, not yet validated against the caller's schema — the service does that. */
  data: unknown;
  model: string;
  usage?: { input: number; output: number };
};

/**
 * A source of AI analysis. Every adapter speaks its own provider's chat-completion API but returns
 * the same shape: parsed JSON plus which model actually answered. A provider is used only when its
 * key (or, for Ollama, its base URL) is configured.
 */
export interface AiProvider {
  readonly info: AiProviderInfo;
  complete(request: AiCompleteRequest): Promise<AiCompleteResult>;
}

/** Why a provider call failed, safe to show: it never carries a key, prompt or response body. */
export type AiFailureReason = "auth" | "rate_limited" | "timeout" | "unavailable" | "bad_response";

export class AiProviderError extends Error {
  constructor(
    readonly reason: AiFailureReason,
    message: string,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = "AiProviderError";
  }
}
