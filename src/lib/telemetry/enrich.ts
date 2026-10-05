import "server-only";
import { writeAuditLog } from "@/lib/audit/write";
import {
  recordExternalIndicators,
  type ExternalIndicatorRecord,
  type RecordSummary,
} from "@/lib/indicators/external";
import { findDisabledProviders } from "@/lib/integrations/repository";
import { LIVE_TIMEOUT_MS, researchLive } from "@/lib/intel/service";
import { buildRegistry, type IntelRegistry } from "@/lib/intel/registry";
import { recordFromLookup } from "@/lib/intel/record";
import { externalSkipReason, parseTarget, type IntelTarget } from "@/lib/intel/target";
import type { ProviderAttempt } from "@/lib/intel/types";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { logError } from "@/lib/log";
import { createAdminClient } from "@/lib/supabase/admin";
import type { IndicatorType } from "@/types/domain";
import type { NormalizedRecord } from "./types";

/*
 * Research on arrival. A sensor alert brings indicators in as "unknown": a sighting, not a verdict.
 * Right after a batch is stored, the indicators nobody has researched yet are asked about at the live
 * providers (VirusTotal, OTX, AbuseIPDB, Shodan: whichever are configured and switched on), and what
 * they say is recorded on the indicator (verdict, confidence, a summary), so a person opens an alert
 * and already finds the answer instead of having to look it up.
 *
 * Bounded on purpose: a few indicators per batch (the free tiers allow only a handful of requests a
 * minute), each at most once (researched_at), and only what may leave the workspace (public
 * addresses and names, never a private one). The rest wait for a later batch. It never runs without
 * a configured provider, never changes an indicator somebody tracks as their own, and never fails
 * the delivery it follows: it runs after the response, and every error is swallowed and logged.
 */

/** Indicators researched per delivery. VirusTotal's free plan answers 4 requests a minute. */
export const MAX_RESEARCHED_PER_BATCH = 4;

const HASH_TYPES = new Set<IndicatorType>(["md5", "sha1", "sha256"]);

/** The lookup subject an indicator of this type is, or null when it cannot be looked up. */
export function targetFor(type: IndicatorType, value: string): IntelTarget | null {
  let parsed;
  if (type === "ipv4" || type === "ipv6") parsed = parseTarget("ip", value);
  else if (type === "domain") parsed = parseTarget("domain", value);
  else if (type === "url") parsed = parseTarget("url", value);
  else if (HASH_TYPES.has(type)) parsed = parseTarget("hash", value);
  else return null;
  return parsed.ok ? parsed.target : null;
}

/** The distinct indicators of a batch that could be looked up, in the order the alerts named them. */
export function candidatesFrom(
  records: readonly NormalizedRecord[],
): { type: IndicatorType; value: string; target: IntelTarget }[] {
  const seen = new Set<string>();
  const found: { type: IndicatorType; value: string; target: IntelTarget }[] = [];
  for (const record of records) {
    if (!record.alert.create) continue; // only alerts bring indicators in
    for (const indicator of record.indicators) {
      const key = `${indicator.type}:${indicator.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const target = targetFor(indicator.type, indicator.value);
      if (target) found.push({ type: indicator.type, value: indicator.value, target });
    }
  }
  return found;
}

export type EnrichSummary = {
  candidates: number;
  researched: number;
  recorded: RecordSummary;
};

export type EnrichDeps = {
  registry: IntelRegistry;
  now: () => Date;
  timeoutMs: number;
  /** Which of these indicators are external, still unresearched and unknown (the ones worth asking about). */
  findUnresearched: (
    items: readonly { type: IndicatorType; value: string }[],
  ) => Promise<Set<string>>;
  disabledProviders: () => Promise<ReadonlySet<string>>;
  research: typeof researchLive;
  record: typeof recordExternalIndicators;
  audit: typeof writeAuditLog;
};

export async function defaultEnrichDeps(): Promise<EnrichDeps> {
  return {
    registry: buildRegistry(await getEffectiveEnv()),
    now: () => new Date(),
    timeoutMs: LIVE_TIMEOUT_MS,
    findUnresearched: async (items) => {
      if (items.length === 0) return new Set();
      const { data, error } = await createAdminClient()
        .from("indicators")
        .select("type, value_normalized")
        .eq("origin", "external")
        .eq("verdict", "unknown")
        .is("researched_at", null)
        .in(
          "value_normalized",
          items.map((item) => (item.type === "url" ? item.value : item.value.toLowerCase())),
        );
      if (error) throw new Error(error.message);
      return new Set(data.map((row) => `${row.type}:${row.value_normalized}`));
    },
    disabledProviders: () => findDisabledProviders(createAdminClient()),
    research: researchLive,
    record: recordExternalIndicators,
    audit: writeAuditLog,
  };
}

const none: RecordSummary = { created: 0, updated: 0, untouched: 0, skipped: 0 };

/**
 * Researches the new indicators of a stored batch. Sequential: one indicator at a time keeps a burst
 * of alerts from firing more requests at once than a free plan allows.
 */
export async function enrichIngestedIndicators(
  records: readonly NormalizedRecord[],
  request?: { headers: Headers },
  providedDeps?: EnrichDeps,
): Promise<EnrichSummary> {
  const candidates = candidatesFrom(records);
  const summary: EnrichSummary = { candidates: candidates.length, researched: 0, recorded: none };
  if (candidates.length === 0) return summary;
  const deps = providedDeps ?? (await defaultEnrichDeps());
  if (deps.registry.external.length === 0) return summary;

  try {
    const disabled = await deps.disabledProviders();
    const registry: IntelRegistry = {
      ...deps.registry,
      external: deps.registry.external.filter((provider) => !disabled.has(provider.info.id)),
    };
    if (registry.external.length === 0) return summary;

    const open = await deps.findUnresearched(candidates);
    // Only what may leave the workspace takes one of the few slots (a private or documentation-range
    // address would use one up for nothing).
    const chosen = candidates
      .filter(
        (candidate) =>
          open.has(`${candidate.type}:${key(candidate)}`) &&
          externalSkipReason(candidate.target) === null,
      )
      .slice(0, MAX_RESEARCHED_PER_BATCH);

    const outcomes: {
      type: IndicatorType;
      providers: { provider: string; outcome: ProviderAttempt["status"] }[];
      verdict: string | null;
    }[] = [];
    for (const candidate of chosen) {
      const { results, attempts } = await deps.research(candidate.target, {
        registry,
        now: deps.now,
        timeoutMs: deps.timeoutMs,
      });
      const toRecord =
        recordFromLookup(candidate.target, results) ?? noAnswerRecord(candidate, attempts);
      if (toRecord) {
        const stored = await deps.record(toRecord.source, [toRecord.record]);
        summary.recorded = {
          created: summary.recorded.created + stored.created,
          updated: summary.recorded.updated + stored.updated,
          untouched: summary.recorded.untouched + stored.untouched,
          skipped: summary.recorded.skipped + stored.skipped,
        };
        summary.researched += 1;
      }
      outcomes.push({
        type: candidate.type,
        providers: attempts.map((attempt) => ({
          provider: attempt.provider.id,
          outcome: attempt.status,
        })),
        verdict: toRecord?.record.verdict ?? null,
      });
    }

    if (outcomes.length > 0) {
      await deps.audit(
        {
          action: "indicator.researched",
          userId: null,
          entityType: "indicator",
          entityId: "ingest",
          metadata: { trigger: "ingest", candidates: candidates.length, outcomes },
        },
        request,
      );
    }
  } catch (error) {
    logError("telemetry.research_failed", error, {});
  }
  return summary;
}

/**
 * Providers that were asked and answered "I do not know this" still researched it: recording that
 * marks the indicator as researched, so it is not asked about again on every later alert. Providers
 * that failed (a timeout, a rate limit, a rejected key) answered nothing, so nothing is recorded and
 * the indicator is tried again with a later batch.
 */
function noAnswerRecord(
  candidate: { type: IndicatorType; value: string },
  attempts: readonly ProviderAttempt[],
): { source: string; record: ExternalIndicatorRecord } | null {
  const asked = [
    ...new Set(
      attempts
        .filter((attempt) => attempt.status === "not_found" || attempt.status === "ok")
        .map((attempt) => attempt.provider.id),
    ),
  ].sort();
  if (asked.length === 0) return null;
  return {
    source: `lookup:${asked.join(".")}`.slice(0, 60),
    record: {
      type: candidate.type,
      value: candidate.value,
      verdict: "unknown",
      severity: "low",
      confidence: 30,
      description: `Researched automatically when an alert brought it in: ${asked.join(", ")} know nothing about it. That is not proof that it is safe.`,
    },
  };
}

const key = (candidate: { type: IndicatorType; value: string }) =>
  candidate.type === "url" ? candidate.value : candidate.value.toLowerCase();
