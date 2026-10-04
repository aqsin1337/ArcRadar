import type { ExternalIndicatorRecord } from "@/lib/indicators/external";
import type { Severity, Verdict } from "@/types/domain";
import type { IntelTarget } from "./target";
import type { ProviderResult } from "./types";

/*
 * What a live lookup leaves behind in the indicator list. A lookup that a live provider answered is a
 * real observation, so the subject is recorded as an indicator (origin external) and shows up on the
 * Indicators page with its verdict, without anyone typing it in. Demo answers are never recorded:
 * demo data is not intelligence. The rules for what may overwrite what live in the database function.
 */

const VERDICT_RANK: Record<Verdict, number> = {
  unknown: 0,
  benign: 1,
  suspicious: 2,
  malicious: 3,
};

const SEVERITY_FOR: Record<Verdict, Severity> = {
  malicious: "high",
  suspicious: "medium",
  benign: "info",
  unknown: "low",
};

/** Confidence when no provider states one: how sure the verdict itself makes us. */
const DEFAULT_CONFIDENCE: Record<Verdict, number> = {
  malicious: 80,
  suspicious: 55,
  benign: 60,
  unknown: 30,
};

const MAX_DESCRIPTION = 4000;

/** The worst verdict any live provider reached (a provider that said nothing does not count). */
export function worstVerdict(results: readonly ProviderResult[]): Verdict {
  let worst: Verdict = "unknown";
  for (const { profile } of results) {
    if (VERDICT_RANK[profile.reputation.verdict] > VERDICT_RANK[worst]) {
      worst = profile.reputation.verdict;
    }
  }
  return worst;
}

/**
 * The record for the answers of the live providers, or null when there is nothing to record (no
 * answer at all, or only demo answers).
 */
export function recordFromLookup(
  target: IntelTarget,
  results: readonly ProviderResult[],
): { source: string; record: ExternalIndicatorRecord } | null {
  const live = results.filter((result) => result.provider.origin === "external");
  if (live.length === 0) return null;

  const verdict = worstVerdict(live);
  const stated = live
    .filter((result) => result.profile.reputation.verdict === verdict)
    .map((result) => result.profile.reputation.confidence)
    .filter((value): value is number => value !== null);
  const confidence = stated.length > 0 ? Math.max(...stated) : DEFAULT_CONFIDENCE[verdict];

  const lines = live.map(({ provider, profile }) => {
    const summary = profile.reputation.summary ?? `verdict ${profile.reputation.verdict}`;
    return `${provider.name}: ${summary}`;
  });
  const description = `Recorded automatically from a live lookup. ${lines.join(" ")}`.slice(
    0,
    MAX_DESCRIPTION,
  );

  const providerIds = [...new Set(live.map((result) => result.provider.id))].sort();
  return {
    source: `lookup:${providerIds.join(".")}`.slice(0, 60),
    record: {
      type: target.indicatorType,
      value: target.value,
      verdict,
      severity: SEVERITY_FOR[verdict],
      confidence,
      description,
    },
  };
}
