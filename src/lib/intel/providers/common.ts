import type { Detections, EngineFinding, Reputation } from "../types";

/** How many engines must call something malicious before ArcRadar says "malicious" (one or two: "suspicious"). */
export const MALICIOUS_ENGINE_THRESHOLD = 3;

export const totalEngines = (d: Detections) =>
  d.malicious + d.suspicious + d.harmless + d.undetected;

/**
 * A verdict from engine counts. Being conservative is deliberate: no detections means "unknown",
 * never "benign" (engines that saw nothing wrong have not proven anything), and a single engine is
 * "suspicious", not "malicious".
 */
export function reputationFromDetections(detections: Detections): Reputation {
  const total = totalEngines(detections);
  const flagged = detections.malicious + detections.suspicious;
  if (detections.malicious >= MALICIOUS_ENGINE_THRESHOLD) {
    return {
      verdict: "malicious",
      confidence: null,
      summary: `${detections.malicious} of ${total} engines flag this as malicious.`,
    };
  }
  if (flagged > 0) {
    return {
      verdict: "suspicious",
      confidence: null,
      summary: `${flagged} of ${total} engines flag this as malicious or suspicious.`,
    };
  }
  return {
    verdict: "unknown",
    confidence: null,
    summary:
      total > 0
        ? `None of ${total} engines flagged this. That is not proof that it is safe.`
        : "The provider has no analysis results for this.",
  };
}

/** Seconds since the epoch (as VirusTotal reports dates) to ISO, or null. */
export function epochToIso(seconds: number | null | undefined): string | null {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return null;
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function uniqueStrings(values: readonly string[], max: number): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].slice(0, max);
}

type EngineResults = Record<string, { category: string; result?: string | null | undefined }>;

/** The engines that flagged something, worst first, capped so a page stays readable. */
export function findingsFrom(results: EngineResults | undefined, max = 12): EngineFinding[] {
  if (!results) return [];
  const flagged: EngineFinding[] = [];
  for (const [engine, entry] of Object.entries(results)) {
    if (entry.category === "malicious" || entry.category === "suspicious") {
      flagged.push({ engine, category: entry.category, result: entry.result ?? null });
    }
  }
  return flagged
    .sort(
      (a, b) =>
        Number(b.category === "malicious") - Number(a.category === "malicious") ||
        a.engine.localeCompare(b.engine),
    )
    .slice(0, max);
}
