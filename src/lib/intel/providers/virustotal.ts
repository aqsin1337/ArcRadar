import "server-only";
import { z } from "zod";
import { getJson, pathSegment } from "../http";
import {
  ProviderError,
  type DomainProfile,
  type HashProfile,
  type HashType,
  type IntelProvider,
  type IpProfile,
  type LookupContext,
  type ProviderInfo,
  type UrlProfile,
} from "../types";
import { epochToIso, findingsFrom, reputationFromDetections, uniqueStrings } from "./common";

const BASE_URL = "https://www.virustotal.com/api/v3";

const stats = z.object({
  malicious: z.number().default(0),
  suspicious: z.number().default(0),
  harmless: z.number().default(0),
  undetected: z.number().default(0),
});

const analysis = {
  last_analysis_stats: stats.nullish(),
  last_analysis_results: z
    .record(z.string(), z.object({ category: z.string(), result: z.string().nullish() }))
    .nullish(),
  last_analysis_date: z.number().nullish(),
  tags: z.array(z.string()).nullish(),
};

const categories = z.record(z.string(), z.string()).nullish();

const ipAttributes = z.object({
  ...analysis,
  asn: z.number().nullish(),
  as_owner: z.string().nullish(),
  country: z.string().nullish(),
  network: z.string().nullish(),
});

const domainAttributes = z.object({
  ...analysis,
  registrar: z.string().nullish(),
  creation_date: z.number().nullish(),
  last_update_date: z.number().nullish(),
  last_dns_records: z
    .array(z.object({ type: z.string(), value: z.string(), ttl: z.number().nullish() }))
    .nullish(),
  categories,
});

const urlAttributes = z.object({
  ...analysis,
  last_final_url: z.string().nullish(),
  title: z.string().nullish(),
  last_http_response_code: z.number().nullish(),
  redirection_chain: z.array(z.string()).nullish(),
  first_submission_date: z.number().nullish(),
  categories,
});

const fileAttributes = z.object({
  ...analysis,
  meaningful_name: z.string().nullish(),
  names: z.array(z.string()).nullish(),
  size: z.number().nullish(),
  type_description: z.string().nullish(),
  md5: z.string().nullish(),
  sha1: z.string().nullish(),
  sha256: z.string().nullish(),
  first_submission_date: z.number().nullish(),
  popular_threat_classification: z
    .object({
      suggested_threat_label: z.string().nullish(),
      popular_threat_name: z.array(z.object({ value: z.string() })).nullish(),
    })
    .nullish(),
});

const envelope = z.object({ data: z.object({ attributes: z.unknown() }) });

type AnalysisAttributes = {
  last_analysis_stats?: z.output<typeof stats> | null;
  last_analysis_results?: Record<string, { category: string; result?: string | null }> | null;
  last_analysis_date?: number | null;
  tags?: string[] | null;
};

function common(attributes: AnalysisAttributes, context: LookupContext) {
  const detections = attributes.last_analysis_stats ?? null;
  return {
    retrieved_at: context.now.toISOString(),
    reputation: detections
      ? reputationFromDetections(detections)
      : {
          verdict: "unknown" as const,
          confidence: null,
          summary: "VirusTotal has no analysis results for this.",
        },
    detections,
    findings: findingsFrom(attributes.last_analysis_results ?? undefined),
    tags: uniqueStrings(attributes.tags ?? [], 20),
    last_analysed_at: epochToIso(attributes.last_analysis_date),
  };
}

/**
 * VirusTotal API v3 (https://docs.virustotal.com/reference). Only reads what VirusTotal already
 * knows: ArcRadar never uploads a file and never asks VirusTotal to scan a URL, so a lookup cannot
 * make VirusTotal (or anyone else) contact the subject. A 404 means "VirusTotal has no record".
 */
export class VirusTotalProvider implements IntelProvider {
  readonly info: ProviderInfo = { id: "virustotal", name: "VirusTotal", origin: "external" };
  private readonly apiKey: string;
  private readonly fetchImpl?: typeof fetch;

  constructor(options: { apiKey: string; fetchImpl?: typeof fetch }) {
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl;
  }

  private async attributes<S extends z.ZodType>(
    path: string,
    schema: S,
    context: LookupContext,
  ): Promise<z.output<S> | null> {
    const body = await getJson({
      baseUrl: BASE_URL,
      path,
      headers: { "x-apikey": this.apiKey },
      signal: context.signal,
      fetchImpl: this.fetchImpl,
    });
    if (body === null) return null;

    const outer = envelope.safeParse(body);
    const inner = outer.success ? schema.safeParse(outer.data.data.attributes) : null;
    if (!inner || !inner.success) {
      throw new ProviderError("bad_response", "VirusTotal answered in an unexpected format.");
    }
    return inner.data;
  }

  async lookupIp(ip: string, context: LookupContext): Promise<IpProfile | null> {
    const a = await this.attributes(`/ip_addresses/${pathSegment(ip)}`, ipAttributes, context);
    if (!a) return null;
    return {
      kind: "ip",
      ip,
      version: ip.includes(":") ? 6 : 4,
      network: a.network ?? null,
      asn: a.asn ?? null,
      organization: a.as_owner ?? null,
      isp: null,
      usage_type: null,
      country: a.country ?? null,
      region: null,
      city: null,
      hostnames: [],
      open_ports: [],
      related_domains: [],
      report_count: null,
      last_reported_at: null,
      ...common(a, context),
    };
  }

  async lookupDomain(domain: string, context: LookupContext): Promise<DomainProfile | null> {
    const a = await this.attributes(`/domains/${pathSegment(domain)}`, domainAttributes, context);
    if (!a) return null;
    const records = (a.last_dns_records ?? []).slice(0, 50).map((record) => ({
      type: record.type,
      value: record.value,
      ttl: record.ttl ?? null,
    }));
    const values = (type: string[]) =>
      uniqueStrings(
        records.filter((record) => type.includes(record.type)).map((record) => record.value),
        20,
      );
    return {
      kind: "domain",
      domain,
      registrar: a.registrar ?? null,
      created_at: epochToIso(a.creation_date),
      updated_at: epochToIso(a.last_update_date),
      expires_at: null,
      nameservers: values(["NS"]),
      dns_records: records,
      related_ips: values(["A", "AAAA"]),
      categories: uniqueStrings(Object.values(a.categories ?? {}), 10),
      ...common(a, context),
    };
  }

  async lookupUrl(url: string, context: LookupContext): Promise<UrlProfile | null> {
    // VirusTotal identifies a URL by its unpadded base64url encoding.
    const id = Buffer.from(url, "utf8").toString("base64url");
    const a = await this.attributes(`/urls/${pathSegment(id)}`, urlAttributes, context);
    if (!a) return null;
    return {
      kind: "url",
      url,
      host: new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase(),
      final_url: a.last_final_url ?? null,
      redirect_chain: uniqueStrings(a.redirection_chain ?? [], 10),
      http_status: a.last_http_response_code ?? null,
      title: a.title ?? null,
      categories: uniqueStrings(Object.values(a.categories ?? {}), 10),
      first_submitted_at: epochToIso(a.first_submission_date),
      ...common(a, context),
    };
  }

  async lookupHash(
    hash: string,
    type: HashType,
    context: LookupContext,
  ): Promise<HashProfile | null> {
    const a = await this.attributes(`/files/${pathSegment(hash)}`, fileAttributes, context);
    if (!a) return null;
    const classification = a.popular_threat_classification;
    return {
      kind: "hash",
      hash,
      hash_type: type,
      hashes: { md5: a.md5 ?? null, sha1: a.sha1 ?? null, sha256: a.sha256 ?? null },
      malware_families: uniqueStrings(
        [
          classification?.suggested_threat_label ?? "",
          ...(classification?.popular_threat_name ?? []).map((name) => name.value),
        ],
        6,
      ),
      file_name: a.meaningful_name ?? null,
      file_names: uniqueStrings(a.names ?? [], 10),
      file_type: a.type_description ?? null,
      file_size: a.size ?? null,
      first_submitted_at: epochToIso(a.first_submission_date),
      ...common(a, context),
    };
  }
}
