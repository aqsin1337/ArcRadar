import type { IndicatorType } from "@/types/domain";
import type { IntelKind } from "./types";

/** The lookup page that fits an indicator type, or null when the type has none (email, CVE, other). */
export function intelKindOf(type: IndicatorType): IntelKind | null {
  switch (type) {
    case "ipv4":
    case "ipv6":
      return "ip";
    case "domain":
      return "domain";
    case "url":
      return "url";
    case "md5":
    case "sha1":
    case "sha256":
      return "hash";
    default:
      return null;
  }
}

export const INTEL_KIND_LABELS: Record<IntelKind, string> = {
  ip: "IP intelligence",
  domain: "Domain intelligence",
  url: "URL analysis",
  hash: "Hash lookup",
};

/** What one lookup subject is called in a sentence ("Look up this ___"). */
export const INTEL_SUBJECT_LABELS: Record<IntelKind, string> = {
  ip: "IP address",
  domain: "domain",
  url: "URL",
  hash: "file hash",
};

export const INTEL_DESCRIPTIONS: Record<IntelKind, string> = {
  ip: "Reputation, network ownership, location and related domains for an IPv4 or IPv6 address, together with what your workspace already knows about it.",
  domain:
    "Registration, DNS records, nameservers and reputation for a domain, together with what your workspace already knows about it.",
  url: "Reputation, detections and redirects for a URL. ArcRadar never opens the URL: it only asks providers about it.",
  hash: "Reputation, detections, malware family and file details for an MD5, SHA-1 or SHA-256 hash.",
};

export const INTEL_PLACEHOLDERS: Record<IntelKind, string> = {
  ip: "198.51.100.23 or 2001:db8::1",
  domain: "harbor-lights-c2.example",
  url: "https://login-secure-update.example/account/verify",
  hash: "MD5, SHA-1 or SHA-256",
};

export const intelHref = (kind: IntelKind, value?: string) =>
  value ? `/intelligence/${kind}?q=${encodeURIComponent(value)}` : `/intelligence/${kind}`;
