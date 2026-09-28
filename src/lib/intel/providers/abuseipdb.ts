import "server-only";
import { z } from "zod";
import { getJson } from "../http";
import {
  ProviderError,
  type IntelProvider,
  type IpProfile,
  type LookupContext,
  type ProviderInfo,
  type Reputation,
} from "../types";
import { uniqueStrings } from "./common";

const BASE_URL = "https://api.abuseipdb.com/api/v2";
const MAX_AGE_DAYS = 90;

const answer = z.object({
  data: z.object({
    ipAddress: z.string(),
    abuseConfidenceScore: z.number(),
    isWhitelisted: z.boolean().nullish(),
    countryCode: z.string().nullish(),
    usageType: z.string().nullish(),
    isp: z.string().nullish(),
    domain: z.string().nullish(),
    hostnames: z.array(z.string()).nullish(),
    isTor: z.boolean().nullish(),
    totalReports: z.number().nullish(),
    lastReportedAt: z.string().nullish(),
  }),
});

/** AbuseIPDB's own scale: 75 and above is "malicious", 25 and above "suspicious". */
export function reputationFromAbuseScore(
  score: number,
  whitelisted: boolean,
  reports: number,
): Reputation {
  const summary = `Abuse confidence score ${score} of 100, from ${reports} ${reports === 1 ? "report" : "reports"} in the last ${MAX_AGE_DAYS} days.`;
  if (score >= 75) return { verdict: "malicious", confidence: score, summary };
  if (score >= 25) return { verdict: "suspicious", confidence: score, summary };
  if (whitelisted) {
    return {
      verdict: "benign",
      confidence: null,
      summary: "AbuseIPDB lists this address as allow-listed.",
    };
  }
  return { verdict: "unknown", confidence: null, summary };
}

/** AbuseIPDB API v2, the `check` endpoint (https://docs.abuseipdb.com). IP addresses only. */
export class AbuseIpdbProvider implements IntelProvider {
  readonly info: ProviderInfo = { id: "abuseipdb", name: "AbuseIPDB", origin: "external" };
  private readonly apiKey: string;
  private readonly fetchImpl?: typeof fetch;

  constructor(options: { apiKey: string; fetchImpl?: typeof fetch }) {
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl;
  }

  async lookupIp(ip: string, context: LookupContext): Promise<IpProfile | null> {
    const body = await getJson({
      baseUrl: BASE_URL,
      path: "/check",
      query: { ipAddress: ip, maxAgeInDays: String(MAX_AGE_DAYS) },
      headers: { Key: this.apiKey },
      signal: context.signal,
      fetchImpl: this.fetchImpl,
    });
    if (body === null) return null;

    const parsed = answer.safeParse(body);
    if (!parsed.success) {
      throw new ProviderError("bad_response", "AbuseIPDB answered in an unexpected format.");
    }
    const d = parsed.data.data;
    const reports = d.totalReports ?? 0;
    const lastReported = d.lastReportedAt ? new Date(d.lastReportedAt) : null;

    return {
      kind: "ip",
      ip,
      version: ip.includes(":") ? 6 : 4,
      network: null,
      asn: null,
      organization: d.isp ?? null,
      isp: d.isp ?? null,
      usage_type: d.usageType ?? null,
      country: d.countryCode ?? null,
      region: null,
      city: null,
      hostnames: uniqueStrings(d.hostnames ?? [], 10),
      open_ports: [],
      related_domains: uniqueStrings(d.domain ? [d.domain] : [], 5),
      report_count: reports,
      last_reported_at:
        lastReported && !Number.isNaN(lastReported.getTime()) ? lastReported.toISOString() : null,
      retrieved_at: context.now.toISOString(),
      reputation: reputationFromAbuseScore(
        d.abuseConfidenceScore,
        d.isWhitelisted === true,
        reports,
      ),
      detections: null,
      findings: [],
      tags: d.isTor ? ["tor"] : [],
      last_analysed_at: null,
    };
  }
}
