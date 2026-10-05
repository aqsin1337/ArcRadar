import "server-only";
import { z } from "zod";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { logError, logWarn } from "@/lib/log";
import { recordExternalIndicators, type RecordSummary } from "@/lib/indicators/external";
import { loadLocalContext } from "./local";
import { recordFromLookup } from "./record";
import { buildRegistry, supportsKind, type IntelRegistry } from "./registry";
import { externalSkipReason, parseTarget, MAX_TARGET_LENGTH, type IntelTarget } from "./target";
import type { LocalContext } from "./timeline";
import {
  INTEL_KINDS,
  ProviderError,
  type FailureReason,
  type IntelKind,
  type IntelProfile,
  type IntelProvider,
  type LookupContext,
  type ProviderAttempt,
  type ProviderInfo,
  type ProviderResult,
} from "./types";
import type { IndicatorType } from "@/types/domain";

export const intelKindSchema = z.enum(INTEL_KINDS);

/** Query string of GET /api/intel/:kind. */
export const intelQuerySchema = z.object({
  value: z.string().trim().min(1, "Enter a value to look up.").max(MAX_TARGET_LENGTH),
});

/** Turns the value typed by a user into a target, or a 422 that names the problem. */
export function requireTarget(kind: IntelKind, value: string): IntelTarget {
  const parsed = parseTarget(kind, value);
  if (!parsed.ok)
    throw apiErrors.validation({ issues: [{ path: "value", message: parsed.error }] });
  return parsed.target;
}

export type LookupResult = {
  kind: IntelKind;
  /** The canonical value that was looked up. */
  value: string;
  /** The type the value would have as an indicator. */
  indicator_type: IndicatorType;
  /** Every provider that answered, each with its own provenance. */
  results: ProviderResult[];
  /** What happened with every provider that was considered, answered or not. */
  attempts: ProviderAttempt[];
  /** Live providers that are connected and could answer this kind of lookup. */
  live_providers: ProviderInfo[];
  /** Whether the caller may trigger live lookups (analysts and administrators). */
  live_allowed: boolean;
  /** True when demo data is shown although live providers are connected (they did not deliver). */
  fallback: boolean;
  local: LocalContext;
  /**
   * What became of the subject in the indicator list: recorded for the first time, refreshed, left
   * alone because the workspace already tracks it as its own, or not recorded (`null`: no live
   * provider answered, so there was nothing real to record).
   */
  recorded: "created" | "updated" | "untouched" | null;
};

export type LookupDeps = {
  registry: IntelRegistry;
  now: () => Date;
  /** Deadline for the live providers, all asked in parallel. */
  timeoutMs: number;
  loadLocal: (auth: AuthContext, target: IntelTarget) => Promise<LocalContext>;
  audit: typeof writeAuditLog;
  /** Stores what a live lookup learned as an indicator (service role, after authorization). */
  record: typeof recordExternalIndicators;
};

// AlienVault OTX answers a domain or URL lookup in anywhere from one to ten seconds; the providers all run in
// parallel under this one deadline, so a slow one costs only itself (it shows as failed, timeout).
export const LIVE_TIMEOUT_MS = 15000;

export async function defaultDeps(): Promise<LookupDeps> {
  return {
    registry: buildRegistry(await getEffectiveEnv()),
    now: () => new Date(),
    timeoutMs: LIVE_TIMEOUT_MS,
    loadLocal: (auth, target) => loadLocalContext(auth.supabase, target),
    audit: writeAuditLog,
    record: recordExternalIndicators,
  };
}

function recordedOutcome(summary: RecordSummary): LookupResult["recorded"] {
  if (summary.created > 0) return "created";
  if (summary.updated > 0) return "updated";
  if (summary.untouched > 0) return "untouched";
  return null;
}

function ask(
  provider: IntelProvider,
  target: IntelTarget,
  context: LookupContext,
): Promise<IntelProfile | null> {
  switch (target.kind) {
    case "ip":
      return provider.lookupIp?.(target.value, context) ?? Promise.resolve(null);
    case "domain":
      return provider.lookupDomain?.(target.value, context) ?? Promise.resolve(null);
    case "url":
      return provider.lookupUrl?.(target.value, context) ?? Promise.resolve(null);
    case "hash":
      return provider.lookupHash?.(target.value, target.hashType, context) ?? Promise.resolve(null);
  }
}

/** Asks one provider and turns any outcome into an attempt; a provider can never make the lookup throw. */
async function tryProvider(
  provider: IntelProvider,
  target: IntelTarget,
  context: LookupContext,
): Promise<{ attempt: ProviderAttempt; profile: IntelProfile | null }> {
  const info = provider.info;
  try {
    const profile = await ask(provider, target, context);
    return profile
      ? { attempt: { provider: info, status: "ok" }, profile }
      : { attempt: { provider: info, status: "not_found" }, profile: null };
  } catch (error) {
    let reason: FailureReason = "unavailable";
    let retryAfter: number | null = null;
    if (error instanceof ProviderError) {
      reason = error.reason;
      retryAfter = error.retryAfterSeconds;
      logWarn("intel.provider_failed", { provider: info.id, kind: target.kind, reason });
    } else {
      logError("intel.provider_error", error, { provider: info.id, kind: target.kind });
    }
    return {
      attempt: { provider: info, status: "failed", reason, retry_after_seconds: retryAfter },
      profile: null,
    };
  }
}

/**
 * Asks every live provider about a subject with nobody signed in: the research ArcRadar starts by
 * itself when a sensor alert brings a new indicator in. The same rules as a person's lookup apply to
 * what may leave the workspace (never a private or reserved address, never a URL with credentials),
 * and the demo provider is never used: an answer is either real or there is none. Nothing throws; a
 * provider that could not answer is simply missing from `results`.
 */
export async function researchLive(
  target: IntelTarget,
  deps: Pick<LookupDeps, "registry" | "now" | "timeoutMs">,
): Promise<{ results: ProviderResult[]; attempts: ProviderAttempt[] }> {
  const live = deps.registry.external.filter((provider) => supportsKind(provider, target.kind));
  if (live.length === 0 || externalSkipReason(target)) return { results: [], attempts: [] };
  const context = { signal: AbortSignal.timeout(deps.timeoutMs), now: deps.now() };
  const answers = await Promise.all(live.map((provider) => tryProvider(provider, target, context)));
  return {
    results: answers.flatMap(({ attempt, profile }) =>
      profile ? [{ provider: attempt.provider, profile }] : [],
    ),
    attempts: answers.map(({ attempt }) => attempt),
  };
}

/** The value as it goes into the audit trail: a URL loses its query string and fragment (they may hold tokens). */
function auditSubject(target: IntelTarget): string {
  if (target.kind !== "url") return target.value;
  try {
    const url = new URL(target.value);
    return `${url.origin}${url.pathname}`.slice(0, 300);
  } catch {
    return target.host;
  }
}

/**
 * Looks a subject up. Live providers are asked only when the caller may (analysts and
 * administrators), the subject may leave the workspace (never a private or reserved address, never a
 * URL with credentials) and a key is configured; they run in parallel under one deadline. When none
 * of them delivers, the demo provider answers, and the result says so: demo data is always labelled
 * and is never mixed into live answers. The workspace's own knowledge about the subject comes along.
 */
export async function lookupIntel(
  auth: AuthContext,
  target: IntelTarget,
  request: { headers: Headers },
  providedDeps?: LookupDeps,
): Promise<LookupResult> {
  const deps = providedDeps ?? (await defaultDeps());
  const { registry } = deps;
  const live = registry.external.filter((provider) => supportsKind(provider, target.kind));
  const liveAllowed = auth.permissions.has("indicators:write");
  const skipReason = externalSkipReason(target);
  let local = deps.loadLocal(auth, target);
  // A rejection is awaited below; this keeps it from being reported as unhandled while providers run.
  local.catch(() => undefined);

  const attempts: ProviderAttempt[] = [];
  const results: ProviderResult[] = [];
  let contacted = false;

  if (live.length > 0) {
    const notAsked = liveAllowed ? skipReason : "not_permitted";
    if (notAsked) {
      for (const provider of live) {
        attempts.push({ provider: provider.info, status: "skipped", reason: notAsked });
      }
    } else {
      contacted = true;
      const context = { signal: AbortSignal.timeout(deps.timeoutMs), now: deps.now() };
      const answers = await Promise.all(
        live.map((provider) => tryProvider(provider, target, context)),
      );
      for (const { attempt, profile } of answers) {
        attempts.push(attempt);
        if (profile) results.push({ provider: attempt.provider, profile });
      }
    }
  }

  let fallback = false;
  if (results.length === 0) {
    const context = { signal: AbortSignal.timeout(deps.timeoutMs), now: deps.now() };
    const { attempt, profile } = await tryProvider(registry.demo, target, context);
    attempts.push(attempt);
    if (profile) {
      results.push({ provider: attempt.provider, profile });
      fallback = live.length > 0;
    }
  }

  if (contacted) {
    // Data left the workspace: record who asked which providers about what.
    await deps.audit(
      {
        action: "intel.lookup",
        userId: auth.user.id,
        entityType: "intel",
        entityId: auditSubject(target),
        metadata: {
          kind: target.kind,
          providers: attempts
            .filter((attempt) => attempt.provider.origin === "external")
            .map((attempt) => ({ provider: attempt.provider.id, outcome: attempt.status })),
        },
      },
      request,
    );
  }

  // A live answer is a real observation: put the subject in the indicator list, so nobody has to
  // type it in. A failure here never fails the lookup that already succeeded.
  let recorded: LookupResult["recorded"] = null;
  const toRecord = contacted ? recordFromLookup(target, results) : null;
  if (toRecord) {
    try {
      recorded = recordedOutcome(await deps.record(toRecord.source, [toRecord.record]));
      if (recorded === "created" || recorded === "updated") {
        local = deps.loadLocal(auth, target); // now it knows the indicator
        local.catch(() => undefined);
        await deps.audit(
          {
            action: "indicator.recorded_from_lookup",
            userId: auth.user.id,
            entityType: "indicator",
            entityId: `${target.indicatorType}:${auditSubject(target)}`,
            metadata: {
              outcome: recorded,
              source: toRecord.source,
              verdict: toRecord.record.verdict,
            },
          },
          request,
        );
      }
    } catch (error) {
      logError("intel.record_failed", error, { kind: target.kind });
    }
  }

  return {
    kind: target.kind,
    value: target.value,
    indicator_type: target.indicatorType,
    results,
    attempts,
    live_providers: live.map((provider) => provider.info),
    live_allowed: liveAllowed,
    fallback,
    local: await local,
    recorded,
  };
}
