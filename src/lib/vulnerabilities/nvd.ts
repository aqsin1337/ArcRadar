import "server-only";
import { z } from "zod";
import { getJson } from "@/lib/intel/http";
import { ProviderError, type LookupContext, type ProviderInfo } from "@/lib/intel/types";
import type { ExploitStatus, Severity } from "@/types/domain";
import { MAX_AFFECTED_PRODUCTS, MAX_REFERENCES } from "./constants";
import type { VulnerabilityProvider, VulnerabilityRecord } from "./types";

const BASE_URL = "https://services.nvd.nist.gov/rest/json";

const metric = z.object({
  type: z.string().nullish(),
  baseSeverity: z.string().nullish(),
  cvssData: z.object({
    version: z.string(),
    vectorString: z.string().nullish(),
    baseScore: z.number(),
    baseSeverity: z.string().nullish(),
  }),
});
const metricList = z.array(metric).nullish();

const cpeMatch = z.object({
  vulnerable: z.boolean().nullish(),
  criteria: z.string(),
  versionStartIncluding: z.string().nullish(),
  versionStartExcluding: z.string().nullish(),
  versionEndIncluding: z.string().nullish(),
  versionEndExcluding: z.string().nullish(),
});

const cve = z.object({
  id: z.string(),
  published: z.string().nullish(),
  lastModified: z.string().nullish(),
  descriptions: z.array(z.object({ lang: z.string(), value: z.string() })).nullish(),
  metrics: z
    .object({
      cvssMetricV40: metricList,
      cvssMetricV31: metricList,
      cvssMetricV30: metricList,
      cvssMetricV2: metricList,
    })
    .nullish(),
  configurations: z
    .array(
      z.object({ nodes: z.array(z.object({ cpeMatch: z.array(cpeMatch).nullish() })).nullish() }),
    )
    .nullish(),
  references: z.array(z.object({ url: z.string(), tags: z.array(z.string()).nullish() })).nullish(),
  cisaExploitAdd: z.string().nullish(),
  cisaRequiredAction: z.string().nullish(),
  cisaVulnerabilityName: z.string().nullish(),
});

const answer = z.object({ vulnerabilities: z.array(z.object({ cve })).nullish() });

type NvdCve = z.output<typeof cve>;
type Metric = z.output<typeof metric>;

/** NVD writes timestamps in UTC without a zone ("2021-12-10T10:15:09.143"). */
export function nvdDate(value: string | null | undefined): string | null {
  if (!value) return null;
  const zoned = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  const date = new Date(zoned);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** CVSS v3 and v4 rating bands. Version 2 has its own, and NVD states the rating itself. */
export function severityFromScore(
  score: number,
  version: string,
  rating?: string | null,
): Severity {
  if (version.startsWith("2")) {
    const stated = rating?.toLowerCase();
    if (stated === "high" || stated === "medium" || stated === "low") return stated;
    return score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  }
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return score > 0 ? "low" : "info";
}

function pickMetric(metrics: NvdCve["metrics"]): Metric | null {
  for (const list of [
    metrics?.cvssMetricV40,
    metrics?.cvssMetricV31,
    metrics?.cvssMetricV30,
    metrics?.cvssMetricV2,
  ]) {
    if (list && list.length > 0) return list.find((entry) => entry.type === "Primary") ?? list[0];
  }
  return null;
}

/** "cpe:2.3:a:apache:log4j:2.14.1:*:..." to its vendor, product and version (escaped colons kept). */
export function parseCpe(
  criteria: string,
): { vendor: string; product: string; version: string } | null {
  const parts = criteria.split(/(?<!\\):/).map((part) => part.replace(/\\(.)/g, "$1"));
  if (
    parts.length < 6 ||
    parts[0] !== "cpe" ||
    !parts[3] ||
    !parts[4] ||
    parts[3] === "*" ||
    parts[4] === "*"
  ) {
    return null;
  }
  return { vendor: parts[3], product: parts[4], version: parts[5] };
}

function versionText(match: z.output<typeof cpeMatch>, version: string): string | null {
  const bounds = [
    match.versionStartIncluding && `>= ${match.versionStartIncluding}`,
    match.versionStartExcluding && `> ${match.versionStartExcluding}`,
    match.versionEndIncluding && `<= ${match.versionEndIncluding}`,
    match.versionEndExcluding && `< ${match.versionEndExcluding}`,
  ].filter(Boolean);
  if (bounds.length > 0) return bounds.join(", ");
  if (version === "*") return "All versions";
  return version === "-" ? null : version;
}

function affectedProducts(
  configurations: NvdCve["configurations"],
): VulnerabilityRecord["affected_products"] {
  const seen = new Map<string, VulnerabilityRecord["affected_products"][number]>();
  for (const configuration of configurations ?? []) {
    for (const node of configuration.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        if (match.vulnerable === false) continue;
        const cpe = parseCpe(match.criteria);
        if (!cpe) continue;
        const versions = versionText(match, cpe.version);
        const key = `${cpe.vendor}|${cpe.product}|${versions}`;
        if (!seen.has(key)) {
          seen.set(key, {
            vendor: cpe.vendor,
            product: cpe.product,
            affected_versions: versions,
            fixed_version: match.versionEndExcluding ?? null,
          });
        }
      }
    }
  }
  return [...seen.values()].slice(0, MAX_AFFECTED_PRODUCTS);
}

function titleFor(record: NvdCve, description: string): string {
  const named = record.cisaVulnerabilityName?.trim();
  if (named) return named.slice(0, 300);
  const firstSentence = description.split(/(?<=\.)\s/)[0]?.trim() ?? "";
  return (firstSentence || record.id).slice(0, 200);
}

/** Maps NVD's CVE document to ArcRadar's vulnerability record. */
export function mapNvdCve(record: NvdCve): VulnerabilityRecord {
  const description =
    (
      record.descriptions?.find((entry) => entry.lang === "en") ?? record.descriptions?.[0]
    )?.value.trim() ?? "";
  const metricEntry = pickMetric(record.metrics);
  const knownVersion =
    (["2.0", "3.0", "3.1", "4.0"] as const).find((v) => v === metricEntry?.cvssData.version) ??
    null;

  const references = [
    ...new Set(
      (record.references ?? [])
        .map((reference) => reference.url)
        .filter((url) => /^https?:\/\//i.test(url)),
    ),
  ].slice(0, MAX_REFERENCES);
  const hasExploitReference = (record.references ?? []).some((reference) =>
    reference.tags?.includes("Exploit"),
  );
  const exploit: ExploitStatus = record.cisaExploitAdd
    ? "exploited_in_wild"
    : hasExploitReference
      ? "poc_available"
      : "unknown";

  return {
    cve_id: record.id.toUpperCase(),
    title: titleFor(record, description),
    description,
    cvss_score: metricEntry?.cvssData.baseScore ?? null,
    cvss_vector: metricEntry?.cvssData.vectorString ?? null,
    cvss_version: knownVersion,
    // A CVE NVD has not scored yet is shown as "info" with no score, never as a guess.
    severity: metricEntry
      ? severityFromScore(
          metricEntry.cvssData.baseScore,
          metricEntry.cvssData.version,
          metricEntry.cvssData.baseSeverity ?? metricEntry.baseSeverity,
        )
      : "info",
    exploit_status: exploit,
    remediation: record.cisaRequiredAction?.trim() || null,
    reference_urls: references,
    published_at: nvdDate(record.published),
    modified_at: nvdDate(record.lastModified),
    affected_products: affectedProducts(record.configurations),
  };
}

/**
 * NVD, the US National Vulnerability Database (CVE API 2.0, https://nvd.nist.gov/developers).
 * Read-only lookups by CVE id; an unknown id answers `null`.
 */
export class NvdProvider implements VulnerabilityProvider {
  readonly info: ProviderInfo = { id: "nvd", name: "NVD", origin: "external" };
  private readonly apiKey: string;
  private readonly fetchImpl?: typeof fetch;

  constructor(options: { apiKey: string; fetchImpl?: typeof fetch }) {
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl;
  }

  async lookupCve(cveId: string, context: LookupContext): Promise<VulnerabilityRecord | null> {
    const body = await getJson({
      baseUrl: BASE_URL,
      path: "/cves/2.0",
      query: { cveId },
      headers: { apiKey: this.apiKey },
      signal: context.signal,
      fetchImpl: this.fetchImpl,
      // NVD answers a rejected key with 404 and "Invalid apiKey." in a `message` header: that is a
      // configuration problem, not "no such CVE".
      onNotFound: (headers) =>
        /api\s?key/i.test(headers.get("message") ?? "")
          ? new ProviderError("auth", "The provider rejected the API key.")
          : null,
    });
    if (body === null) return null;

    const parsed = answer.safeParse(body);
    if (!parsed.success) {
      throw new ProviderError("bad_response", "NVD answered in an unexpected format.");
    }
    const found = parsed.data.vulnerabilities?.find(
      (entry) => entry.cve.id.toUpperCase() === cveId,
    );
    return found ? mapNvdCve(found.cve) : null;
  }
}
