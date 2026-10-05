import "server-only";
import { z } from "zod";
import { apiErrors } from "@/lib/api/errors";
import { getAlert } from "@/lib/alerts/service";
import type { AlertDetail } from "@/lib/alerts/types";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { getIndicator } from "@/lib/indicators/service";
import type { IndicatorDetail } from "@/lib/indicators/types";
import { getIntegrations } from "@/lib/integrations/service";
import { insertChecklistItems } from "@/lib/investigations/repository";
import { getInvestigation } from "@/lib/investigations/service";
import type { InvestigationDetail } from "@/lib/investigations/types";
import { logError, logWarn } from "@/lib/log";
import { seedResponseActionsForAlert } from "@/lib/response-actions/repository";
import {
  AI_MAX_OUTPUT_TOKENS,
  AI_PROMPT_VERSION,
  buildAlertPrompt,
  buildIndicatorPrompt,
  buildInvestigationPrompt,
} from "./prompts";
import { buildAiRegistry, type AiRegistry } from "./registry";
import {
  findAiAnalyses,
  findAiSettings,
  insertAiAnalysis,
  updateAiSettings,
  updateAlertFalsePositiveScore,
  type AiAnalysisRow,
} from "./repository";
import { AI_ANALYSIS_SCHEMAS, falsePositiveScoreSchema, responseActionsSchema } from "./schemas";
import {
  AI_ANALYSIS_KINDS,
  AI_KIND_SUBJECT_TYPE,
  AI_PROVIDER_IDS,
  AiProviderError,
  type AiAnalysisKind,
  type AiAvailability,
  type AiProviderId,
  type AiProviderStatus,
  type AiSubjectType,
  type SubjectAnalyses,
} from "./types";

export const AI_TIMEOUT_MS = 15_000;

export const aiAnalysisKindSchema = z.enum(AI_ANALYSIS_KINDS);

export const aiSettingsPatchSchema = z.strictObject({
  active_provider: z.enum(AI_PROVIDER_IDS).nullable(),
  active_model: z
    .string()
    .trim()
    .min(1, "Enter a model name, or leave the provider empty.")
    .max(200)
    .nullable(),
});

type RequestLike = { headers: Headers };

export type AiDeps = {
  registry: AiRegistry;
  timeoutMs: number;
  audit: typeof writeAuditLog;
};

export async function defaultDeps(): Promise<AiDeps> {
  return {
    registry: buildAiRegistry(await getEffectiveEnv()),
    timeoutMs: AI_TIMEOUT_MS,
    audit: writeAuditLog,
  };
}

function isAiProviderId(value: string): value is AiProviderId {
  return (AI_PROVIDER_IDS as readonly string[]).includes(value);
}

export async function getAiAvailability(supabase: AuthClient): Promise<AiAvailability> {
  const [settings, integrations] = await Promise.all([
    findAiSettings(supabase),
    getIntegrations(supabase),
  ]);

  const providers: AiProviderStatus[] = integrations
    .filter((row) => row.capabilities.includes("ai") && isAiProviderId(row.provider))
    .map((row) => ({
      id: row.provider as AiProviderId,
      name: row.display_name,
      configured: row.configured,
      enabled: row.enabled,
    }));

  const active = settings?.active_provider;
  const activeStatus = active ? providers.find((p) => p.id === active) : undefined;

  return {
    active_provider: (active as AiProviderId | null) ?? null,
    active_model: settings?.active_model ?? null,
    updated_at: settings?.updated_at ?? null,
    providers,
    ready: Boolean(activeStatus?.configured && activeStatus.enabled),
  };
}

export async function setAiAvailability(
  auth: AuthContext,
  input: { active_provider: AiProviderId | null; active_model: string | null },
  request: RequestLike,
): Promise<AiAvailability> {
  if (input.active_provider === null && input.active_model !== null) {
    throw apiErrors.validation({
      issues: [{ path: "active_model", message: "Choose a provider before setting a model." }],
    });
  }

  if (input.active_provider !== null) {
    const current = await getAiAvailability(auth.supabase);
    const provider = current.providers.find((p) => p.id === input.active_provider);
    if (!provider?.configured) {
      throw apiErrors.conflict("That provider has no server-side key configured yet.");
    }
    if (!provider.enabled) {
      throw apiErrors.conflict(
        "That provider is disabled. Enable it on the Integrations page first.",
      );
    }
  }

  await updateAiSettings(auth.supabase, { ...input, updated_by: auth.user.id });

  await writeAuditLog(
    {
      action: "ai.settings_updated",
      userId: auth.user.id,
      entityType: "ai_settings",
      entityId: "singleton",
      metadata: { active_provider: input.active_provider, active_model: input.active_model },
    },
    request,
  );

  return getAiAvailability(auth.supabase);
}

/** Every analysis ever run for one subject, newest first, grouped into "latest per kind" and history. */
export async function listSubjectAnalyses(
  supabase: AuthClient,
  subjectType: AiSubjectType,
  subjectId: string,
): Promise<SubjectAnalyses> {
  const rows = await findAiAnalyses(supabase, subjectType, subjectId);
  const latest: SubjectAnalyses["latest"] = {};
  for (const row of rows) {
    if (!(row.kind in latest)) latest[row.kind] = row;
  }
  return { latest, history: rows };
}

/** Kept for the alert page and its route, which only ever deal with alert-attached analyses. */
export const listAlertAnalyses = (supabase: AuthClient, alertId: string) =>
  listSubjectAnalyses(supabase, "alert", alertId);

function alertPromptContextFrom(alert: AlertDetail) {
  return {
    title: alert.title,
    description: alert.description,
    severity: alert.severity,
    status: alert.status,
    source: alert.source,
    origin: alert.origin,
    createdAt: alert.created_at,
    indicator: alert.indicator
      ? {
          type: alert.indicator.type,
          value: alert.indicator.value,
          verdict: alert.indicator.verdict,
        }
      : null,
    asset: alert.asset ? { name: alert.asset.name, os: alert.asset.os } : null,
    techniques: alert.techniques,
    event: alert.event
      ? { title: alert.event.title, type: alert.event.event_type, severity: alert.event.severity }
      : null,
  };
}

function investigationPromptContextFrom(investigation: InvestigationDetail) {
  return {
    title: investigation.title,
    description: investigation.description,
    status: investigation.status,
    priority: investigation.priority,
    tags: investigation.tags.map((tag) => tag.name),
    indicators: investigation.indicators.map((i) => ({
      type: i.type,
      value: i.value,
      verdict: i.verdict,
    })),
    alerts: investigation.alerts.map((a) => ({
      title: a.title,
      severity: a.severity,
      status: a.status,
    })),
    notes: investigation.notes.filter((n) => n.kind === "note").map((n) => n.body),
  };
}

function indicatorPromptContextFrom(indicator: IndicatorDetail) {
  return {
    type: indicator.type,
    value: indicator.value,
    verdict: indicator.verdict,
    severity: indicator.severity,
    status: indicator.status,
    confidence: indicator.confidence,
    source: indicator.source,
    description: indicator.description,
    tags: indicator.tags.map((tag) => tag.name),
  };
}

/**
 * The shared core: given a prompt already built from data the caller can already read, asks the
 * active AI provider, validates the answer against `kind`'s schema, stores it and audits it. Never
 * automatic: every call here answers one explicit request.
 */
async function runAnalysis(
  auth: AuthContext,
  params: {
    subjectType: AiSubjectType;
    subjectId: string;
    kind: AiAnalysisKind;
    prompt: { system: string; user: string };
  },
  request: RequestLike,
  deps: AiDeps,
): Promise<AiAnalysisRow> {
  if (AI_KIND_SUBJECT_TYPE[params.kind] !== params.subjectType) {
    throw apiErrors.validation({
      issues: [
        { path: "kind", message: `"${params.kind}" is not an analysis kind for this record.` },
      ],
    });
  }

  const availability = await getAiAvailability(auth.supabase);
  if (!availability.ready || !availability.active_provider) {
    throw apiErrors.unavailable(
      "No AI provider is configured. Ask an administrator to set one up on the Integrations page.",
    );
  }

  const provider = deps.registry.get(availability.active_provider);
  if (!provider) {
    // The active provider was selected while configured but its key/URL is gone now (drift).
    throw apiErrors.unavailable(
      "The active AI provider is no longer configured. Ask an administrator to check Integrations.",
    );
  }

  const schema = AI_ANALYSIS_SCHEMAS[params.kind];

  let result: Awaited<ReturnType<typeof provider.complete>>;
  try {
    result = await provider.complete({
      system: params.prompt.system,
      user: params.prompt.user,
      schema,
      maxOutputTokens: AI_MAX_OUTPUT_TOKENS[params.kind],
      signal: AbortSignal.timeout(deps.timeoutMs),
      model: availability.active_model ?? undefined,
    });
  } catch (error) {
    if (error instanceof AiProviderError) {
      logWarn("ai.provider_failed", {
        provider: availability.active_provider,
        kind: params.kind,
        reason: error.reason,
      });
      if (error.reason === "rate_limited")
        throw apiErrors.rateLimited(error.retryAfterSeconds ?? undefined);
      throw apiErrors.unavailable("The AI provider could not answer right now. Try again shortly.");
    }
    logError("ai.provider_error", error, {
      provider: availability.active_provider,
      kind: params.kind,
    });
    throw apiErrors.unavailable("The AI provider could not answer right now. Try again shortly.");
  }

  const parsed = schema.safeParse(result.data);
  if (!parsed.success) {
    logWarn("ai.invalid_answer", {
      provider: availability.active_provider,
      kind: params.kind,
      issues: parsed.error.issues.length,
    });
    throw apiErrors.unavailable("The AI provider's answer could not be used. Try again shortly.");
  }

  const row = await insertAiAnalysis(auth.supabase, {
    kind: params.kind,
    subject_type: params.subjectType,
    subject_id: params.subjectId,
    provider: availability.active_provider,
    model: result.model,
    prompt_version: AI_PROMPT_VERSION,
    content: parsed.data,
  });

  await deps.audit(
    {
      action: "ai.analysis_generated",
      userId: auth.user.id,
      entityType: params.subjectType,
      entityId: params.subjectId,
      metadata: { kind: params.kind, provider: availability.active_provider, model: result.model },
    },
    request,
  );

  return row;
}

/**
 * Generates one analysis for one alert: loads the alert (its own RLS-scoped read decides whether the
 * caller may see it at all), asks the active AI provider, validates the answer, stores it and audits
 * it. `false_positive_score` also caches its score on the alert; `response_actions` also seeds a
 * catalog entry and a `recommended` row per suggestion in the response-action log.
 */
export async function generateAlertAnalysis(
  auth: AuthContext,
  alertId: string,
  kind: AiAnalysisKind,
  request: RequestLike,
  deps?: AiDeps,
): Promise<AiAnalysisRow> {
  const alert = await getAlert(auth.supabase, alertId);
  const prompt = buildAlertPrompt(kind, alertPromptContextFrom(alert));
  const row = await runAnalysis(
    auth,
    { subjectType: "alert", subjectId: alertId, kind, prompt },
    request,
    deps ?? (await defaultDeps()),
  );

  if (kind === "false_positive_score") {
    const score = falsePositiveScoreSchema.parse(row.content).score;
    try {
      await updateAlertFalsePositiveScore(auth.supabase, alertId, score);
    } catch (error) {
      // The analysis itself was saved; the cached score on the alert row is a convenience for
      // sorting the list and is not worth failing the whole request over (RLS may also simply not
      // let this caller write alerts, independent of holding ai:use).
      logError("ai.fp_score_cache_failed", error, { alert_id: alertId });
    }
  }

  if (kind === "response_actions") {
    const { actions } = responseActionsSchema.parse(row.content);
    try {
      await seedResponseActionsForAlert(auth.supabase, alertId, actions);
    } catch (error) {
      // Same reasoning: the analysis card is the primary artifact, seeding the tracked log is a
      // convenience layered on top of it.
      logError("ai.response_actions_seed_failed", error, { alert_id: alertId });
    }
  }

  return row;
}

/**
 * Generates a checklist for one investigation and seeds it into `investigation_checklist_items` as
 * trackable, uncompleted rows (the immutable `ai_analyses` row stays the original suggestion).
 */
export async function generateInvestigationAnalysis(
  auth: AuthContext,
  investigationId: string,
  kind: AiAnalysisKind,
  request: RequestLike,
  deps?: AiDeps,
): Promise<AiAnalysisRow> {
  const investigation = await getInvestigation(auth.supabase, investigationId);
  const prompt = buildInvestigationPrompt(kind, investigationPromptContextFrom(investigation));
  const row = await runAnalysis(
    auth,
    { subjectType: "investigation", subjectId: investigationId, kind, prompt },
    request,
    deps ?? (await defaultDeps()),
  );

  if (kind === "investigation_checklist") {
    const { items } = AI_ANALYSIS_SCHEMAS.investigation_checklist.parse(row.content);
    try {
      await insertChecklistItems(auth.supabase, investigationId, items);
    } catch (error) {
      logError("ai.checklist_seed_failed", error, { investigation_id: investigationId });
    }
  }

  return row;
}

/**
 * Generates a verdict recommendation for one indicator. No side effect: applying it is a normal,
 * audited indicator edit the analyst makes themselves (PATCH /api/indicators/:id), never something
 * this does automatically.
 */
export async function generateIndicatorAnalysis(
  auth: AuthContext,
  indicatorId: string,
  kind: AiAnalysisKind,
  request: RequestLike,
  deps?: AiDeps,
): Promise<AiAnalysisRow> {
  const indicator = await getIndicator(auth.supabase, indicatorId);
  const prompt = buildIndicatorPrompt(kind, indicatorPromptContextFrom(indicator));
  return runAnalysis(
    auth,
    { subjectType: "indicator", subjectId: indicatorId, kind, prompt },
    request,
    deps ?? (await defaultDeps()),
  );
}
