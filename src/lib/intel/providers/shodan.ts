import "server-only";
import { z } from "zod";
import { getJson, pathSegment } from "../http";
import {
  ProviderError,
  type IntelProvider,
  type IpProfile,
  type LookupContext,
  type ProviderInfo,
  type Reputation,
} from "../types";
import { uniqueStrings } from "./common";

const BASE_URL = "https://internetdb.shodan.io";

const answer = z.object({
  ip: z.string().nullish(),
  ports: z.array(z.number()).nullish(),
  hostnames: z.array(z.string()).nullish(),
  tags: z.array(z.string()).nullish(),
  vulns: z.array(z.string()).nullish(),
});

/** Shodan tags that say a host is compromised or hostile, not merely exposed. */
const HOSTILE_TAGS = new Set(["malware", "compromised", "c2", "honeypot", "scanner"]);

/**
 * Shodan InternetDB describes exposure (open ports, known vulnerabilities), not maliciousness, so
 * its verdict is deliberately weak: a hostile tag makes an address "suspicious", everything else is
 * "unknown". It is never "malicious" on its own.
 */
export function reputationFromExposure(input: {
  ports: number;
  vulns: number;
  tags: readonly string[];
}): Reputation {
  const hostile = input.tags.filter((tag) => HOSTILE_TAGS.has(tag.toLowerCase()));
  const exposure = `${input.ports} open ${input.ports === 1 ? "port" : "ports"}, ${input.vulns} known ${input.vulns === 1 ? "vulnerability" : "vulnerabilities"}`;
  if (hostile.length > 0) {
    return {
      verdict: "suspicious",
      confidence: null,
      summary: `Shodan tags this address as ${hostile.join(", ")} (${exposure}).`,
    };
  }
  return {
    verdict: "unknown",
    confidence: null,
    summary: `Shodan exposure data only, not a reputation: ${exposure}.`,
  };
}

/**
 * Shodan InternetDB (https://internetdb.shodan.io), the free, key-less "what does Shodan see on this
 * address" endpoint. IP addresses only. A 404 means Shodan has nothing on the address.
 */
export class ShodanProvider implements IntelProvider {
  readonly info: ProviderInfo = { id: "shodan", name: "Shodan", origin: "external" };
  private readonly fetchImpl?: typeof fetch;

  constructor(options: { fetchImpl?: typeof fetch } = {}) {
    this.fetchImpl = options.fetchImpl;
  }

  async lookupIp(ip: string, context: LookupContext): Promise<IpProfile | null> {
    const body = await getJson({
      baseUrl: BASE_URL,
      path: `/${pathSegment(ip)}`,
      headers: {},
      signal: context.signal,
      fetchImpl: this.fetchImpl,
    });
    if (body === null) return null;
    const parsed = answer.safeParse(body);
    if (!parsed.success) {
      throw new ProviderError("bad_response", "Shodan answered in an unexpected format.");
    }
    const d = parsed.data;
    const ports = [...new Set(d.ports ?? [])].sort((a, b) => a - b).slice(0, 50);
    const vulns = d.vulns ?? [];
    const tags = d.tags ?? [];
    return {
      kind: "ip",
      ip,
      version: ip.includes(":") ? 6 : 4,
      network: null,
      asn: null,
      organization: null,
      isp: null,
      usage_type: null,
      country: null,
      region: null,
      city: null,
      hostnames: uniqueStrings(d.hostnames ?? [], 10),
      open_ports: ports,
      related_domains: [],
      report_count: null,
      last_reported_at: null,
      retrieved_at: context.now.toISOString(),
      reputation: reputationFromExposure({ ports: ports.length, vulns: vulns.length, tags }),
      detections: null,
      findings: [],
      tags: uniqueStrings([...tags, ...vulns], 20),
      last_analysed_at: null,
    };
  }
}
