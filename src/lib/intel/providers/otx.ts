import "server-only";
import { z } from "zod";
import { getJson, pathSegment } from "../http";
import {
  ProviderError,
  type DomainProfile,
  type EngineFinding,
  type HashProfile,
  type HashType,
  type IntelProvider,
  type IpProfile,
  type LookupContext,
  type ProviderInfo,
  type Reputation,
  type UrlProfile,
} from "../types";
import { uniqueStrings } from "./common";

const BASE_URL = "https://otx.alienvault.com/api/v1";

/** How many community pulses must mention a subject before ArcRadar says "malicious". */
export const MALICIOUS_PULSE_THRESHOLD = 3;

const pulse = z.object({
  name: z.string().nullish(),
  tags: z.array(z.string()).nullish(),
  malware_families: z
    .array(z.union([z.string(), z.object({ display_name: z.string() })]))
    .nullish(),
});

const general = z.object({
  pulse_info: z.object({ count: z.number().nullish(), pulses: z.array(pulse).nullish() }).nullish(),
  validation: z.array(z.object({ source: z.string().nullish() })).nullish(),
  country_name: z.string().nullish(),
  country_code: z.string().nullish(),
  region: z.string().nullish(),
  city: z.string().nullish(),
  asn: z.string().nullish(),
  type_title: z.string().nullish(),
  domain: z.string().nullish(),
  hostname: z.string().nullish(),
});

type General = z.output<typeof general>;

/**
 * AlienVault OTX says nothing about maliciousness itself: it lists the community "pulses" (reports)
 * that mention a subject. Being conservative, like the other providers: nothing found is "unknown"
 * (never "benign"), one or two pulses are "suspicious", three or more "malicious", and OTX's own
 * allow-list validation makes a subject "benign".
 */
export function reputationFromPulses(count: number, allowListed: boolean): Reputation {
  if (allowListed) {
    return {
      verdict: "benign",
      confidence: null,
      summary: "OTX validates this as a known-good (allow-listed) indicator.",
    };
  }
  if (count >= MALICIOUS_PULSE_THRESHOLD) {
    return {
      verdict: "malicious",
      confidence: null,
      summary: `Mentioned in ${count} OTX community threat reports (pulses).`,
    };
  }
  if (count > 0) {
    return {
      verdict: "suspicious",
      confidence: null,
      summary: `Mentioned in ${count} OTX community threat ${count === 1 ? "report" : "reports"} (pulses).`,
    };
  }
  return {
    verdict: "unknown",
    confidence: null,
    summary: "No OTX community report mentions this. That is not proof that it is safe.",
  };
}

function summarise(body: General, context: LookupContext) {
  const pulses = body.pulse_info?.pulses ?? [];
  const count = body.pulse_info?.count ?? pulses.length;
  const allowListed = (body.validation ?? []).some((entry) =>
    (entry.source ?? "").toLowerCase().includes("whitelist"),
  );
  const findings: EngineFinding[] = pulses
    .filter((entry) => entry.name)
    .slice(0, 8)
    .map((entry) => ({
      engine: "OTX pulse",
      category: "suspicious" as const,
      result: entry.name ?? null,
    }));
  const families = pulses.flatMap((entry) =>
    (entry.malware_families ?? []).map((family) =>
      typeof family === "string" ? family : family.display_name,
    ),
  );
  return {
    common: {
      retrieved_at: context.now.toISOString(),
      reputation: reputationFromPulses(count, allowListed),
      detections: null,
      findings: allowListed ? [] : findings,
      tags: uniqueStrings(
        pulses.flatMap((entry) => entry.tags ?? []),
        20,
      ),
      last_analysed_at: null,
    },
    families: uniqueStrings(families, 10),
  };
}

/** "AS15169 Google LLC" -> { asn: 15169, organization: "Google LLC" }. */
function parseAsn(value: string | null | undefined): { asn: number | null; org: string | null } {
  const match = /^AS(\d{1,10})\s*(.*)$/i.exec(value ?? "");
  if (!match) return { asn: null, org: null };
  return { asn: Number(match[1]), org: match[2].trim() || null };
}

/**
 * AlienVault OTX API v1 (https://otx.alienvault.com/api), the `general` section of an indicator.
 * Read only: OTX is asked what it already knows. A 404 means "OTX has no record".
 */
export class OtxProvider implements IntelProvider {
  readonly info: ProviderInfo = { id: "otx", name: "AlienVault OTX", origin: "external" };
  private readonly apiKey: string;
  private readonly fetchImpl?: typeof fetch;

  constructor(options: { apiKey: string; fetchImpl?: typeof fetch }) {
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl;
  }

  private async general(
    section: string,
    subject: string,
    context: LookupContext,
  ): Promise<General | null> {
    const body = await getJson({
      baseUrl: BASE_URL,
      path: `/indicators/${section}/${pathSegment(subject)}/general`,
      headers: { "X-OTX-API-KEY": this.apiKey },
      signal: context.signal,
      fetchImpl: this.fetchImpl,
    });
    if (body === null) return null;
    const parsed = general.safeParse(body);
    if (!parsed.success) {
      throw new ProviderError("bad_response", "AlienVault OTX answered in an unexpected format.");
    }
    return parsed.data;
  }

  async lookupIp(ip: string, context: LookupContext): Promise<IpProfile | null> {
    const version = ip.includes(":") ? 6 : 4;
    const body = await this.general(version === 6 ? "IPv6" : "IPv4", ip, context);
    if (!body) return null;
    const { asn, org } = parseAsn(body.asn);
    const { common } = summarise(body, context);
    return {
      kind: "ip",
      ip,
      version,
      network: null,
      asn,
      organization: org,
      isp: null,
      usage_type: null,
      country: body.country_name ?? body.country_code ?? null,
      region: body.region ?? null,
      city: body.city ?? null,
      hostnames: [],
      open_ports: [],
      related_domains: [],
      report_count: body.pulse_info?.count ?? null,
      last_reported_at: null,
      ...common,
    };
  }

  async lookupDomain(domain: string, context: LookupContext): Promise<DomainProfile | null> {
    const body = await this.general("domain", domain, context);
    if (!body) return null;
    const { common } = summarise(body, context);
    return {
      kind: "domain",
      domain,
      registrar: null,
      created_at: null,
      updated_at: null,
      expires_at: null,
      nameservers: [],
      dns_records: [],
      related_ips: [],
      categories: [],
      ...common,
    };
  }

  async lookupUrl(url: string, context: LookupContext): Promise<UrlProfile | null> {
    const body = await this.general("url", url, context);
    if (!body) return null;
    const { common } = summarise(body, context);
    let host = body.hostname ?? body.domain ?? "";
    if (!host) {
      try {
        host = new URL(url).hostname;
      } catch {
        host = "";
      }
    }
    return {
      kind: "url",
      url,
      host,
      final_url: null,
      redirect_chain: [],
      http_status: null,
      title: null,
      categories: [],
      first_submitted_at: null,
      ...common,
    };
  }

  async lookupHash(
    hash: string,
    type: HashType,
    context: LookupContext,
  ): Promise<HashProfile | null> {
    const body = await this.general("file", hash, context);
    if (!body) return null;
    const { common, families } = summarise(body, context);
    return {
      kind: "hash",
      hash,
      hash_type: type,
      hashes: {
        md5: type === "md5" ? hash : null,
        sha1: type === "sha1" ? hash : null,
        sha256: type === "sha256" ? hash : null,
      },
      malware_families: families,
      file_name: null,
      file_names: [],
      file_type: body.type_title ?? null,
      file_size: null,
      first_submitted_at: null,
      ...common,
    };
  }
}
