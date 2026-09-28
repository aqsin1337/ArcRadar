import type { DataOrigin, Verdict } from "@/types/domain";

/**
 * Types shared by the intelligence providers, the lookup service and the pages. Nothing here
 * depends on a particular provider: every provider, real or demo, answers with the same profiles.
 */

export const INTEL_KINDS = ["ip", "domain", "url", "hash"] as const;
export type IntelKind = (typeof INTEL_KINDS)[number];

export const HASH_TYPES = ["md5", "sha1", "sha256"] as const;
export type HashType = (typeof HASH_TYPES)[number];

export type ProviderId = "demo" | "virustotal" | "abuseipdb" | "nvd";

export type ProviderInfo = {
  id: ProviderId;
  name: string;
  /** `demo` for the built-in sample provider, `external` for a connected live service. */
  origin: Exclude<DataOrigin, "local">;
};

/** What a provider concludes. `confidence` is 0-100 and only set when the provider states one. */
export type Reputation = { verdict: Verdict; confidence: number | null; summary: string | null };

/** How many analysis engines reached each conclusion (the VirusTotal model). */
export type Detections = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
};

export type EngineFinding = {
  engine: string;
  category: "malicious" | "suspicious";
  result: string | null;
};

export type DnsRecord = { type: string; value: string; ttl: number | null };

type ProfileBase = {
  /** When this answer was produced (ISO). For a live provider it is the time of the request. */
  retrieved_at: string;
  reputation: Reputation;
  detections: Detections | null;
  findings: EngineFinding[];
  tags: string[];
  /** The latest time the provider says it saw or analysed the subject (ISO), when it says. */
  last_analysed_at: string | null;
};

export type IpProfile = ProfileBase & {
  kind: "ip";
  ip: string;
  version: 4 | 6;
  network: string | null;
  asn: number | null;
  organization: string | null;
  isp: string | null;
  usage_type: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  hostnames: string[];
  open_ports: number[];
  related_domains: string[];
  report_count: number | null;
  last_reported_at: string | null;
};

export type DomainProfile = ProfileBase & {
  kind: "domain";
  domain: string;
  registrar: string | null;
  created_at: string | null;
  updated_at: string | null;
  expires_at: string | null;
  nameservers: string[];
  dns_records: DnsRecord[];
  related_ips: string[];
  categories: string[];
};

export type UrlProfile = ProfileBase & {
  kind: "url";
  url: string;
  host: string;
  final_url: string | null;
  redirect_chain: string[];
  http_status: number | null;
  title: string | null;
  categories: string[];
  first_submitted_at: string | null;
};

export type HashProfile = ProfileBase & {
  kind: "hash";
  hash: string;
  hash_type: HashType;
  hashes: { md5: string | null; sha1: string | null; sha256: string | null };
  malware_families: string[];
  file_name: string | null;
  file_names: string[];
  file_type: string | null;
  file_size: number | null;
  first_submitted_at: string | null;
};

export type IntelProfile = IpProfile | DomainProfile | UrlProfile | HashProfile;

/** Why a live provider was not asked at all. */
export type SkipReason = "not_permitted" | "not_public" | "has_credentials";

/** Why a live provider was asked and did not deliver. */
export type FailureReason = "auth" | "rate_limited" | "timeout" | "unavailable" | "bad_response";

export type ProviderAttempt =
  | { provider: ProviderInfo; status: "ok" }
  | { provider: ProviderInfo; status: "not_found" }
  | {
      provider: ProviderInfo;
      status: "failed";
      reason: FailureReason;
      retry_after_seconds: number | null;
    }
  | { provider: ProviderInfo; status: "skipped"; reason: SkipReason };

export type ProviderResult = { provider: ProviderInfo; profile: IntelProfile };

/** Passed to every lookup: the deadline and the clock (so tests are deterministic). */
export type LookupContext = { signal: AbortSignal; now: Date };

/**
 * A source of intelligence. A provider implements only the lookups it can answer; each returns
 * `null` when the provider has no record of the value, and throws a `ProviderError` when it could
 * not answer. Providers never receive anything but the validated value: the UI and the API never
 * talk to an external service themselves.
 */
export interface IntelProvider {
  readonly info: ProviderInfo;
  lookupIp?(ip: string, context: LookupContext): Promise<IpProfile | null>;
  lookupDomain?(domain: string, context: LookupContext): Promise<DomainProfile | null>;
  lookupUrl?(url: string, context: LookupContext): Promise<UrlProfile | null>;
  lookupHash?(hash: string, type: HashType, context: LookupContext): Promise<HashProfile | null>;
}

/** The failure of a provider call, safe to show: it never carries a key or a response body. */
export class ProviderError extends Error {
  constructor(
    readonly reason: FailureReason,
    message: string,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = "ProviderError";
  }
}
