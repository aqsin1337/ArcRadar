import { z } from "zod";
import { canonicalizeIndicatorValue, validateIndicatorValue } from "@/lib/indicators/value";
import type { HashType, IntelKind, SkipReason } from "./types";

/**
 * What a lookup is about, validated and in the form it is stored and sent. Parsing is strict on
 * purpose: only a well-formed IP address, domain name, http(s) URL or hash can reach a provider, so
 * user input never decides which host an outbound request goes to (providers only ever build
 * requests against their own fixed API address). A value that passes is well-formed, not malicious.
 */
export type IntelTarget =
  | { kind: "ip"; value: string; version: 4 | 6; indicatorType: "ipv4" | "ipv6" }
  | { kind: "domain"; value: string; indicatorType: "domain" }
  | { kind: "url"; value: string; host: string; hasCredentials: boolean; indicatorType: "url" }
  | { kind: "hash"; value: string; hashType: HashType; indicatorType: HashType };

export type TargetResult =
  | { ok: true; target: IntelTarget }
  | { ok: false; error: string; suggestion: { kind: IntelKind; value: string } | null };

export const MAX_TARGET_LENGTH = 2048;

const IP_ERROR = "Enter a valid IPv4 or IPv6 address, such as 203.0.113.10 or 2001:db8::1.";
const HASH_ERROR =
  "Enter an MD5 (32), SHA-1 (40) or SHA-256 (64) hash: hexadecimal characters only.";
const HEX = /^[a-f0-9]+$/i;
const HASH_TYPE_BY_LENGTH: Record<number, HashType> = { 32: "md5", 40: "sha1", 64: "sha256" };

/** Recognizes what a pasted value is, by structure alone. It says nothing about maliciousness. */
export function detectKind(raw: string): { kind: IntelKind | "cve"; value: string } | null {
  const value = raw.trim();
  if (!value || value.length > MAX_TARGET_LENGTH) return null;
  if (validateIndicatorValue("url", value) === null) return { kind: "url", value };
  if (validateIndicatorValue("cve", value) === null)
    return { kind: "cve", value: value.toUpperCase() };
  if (HEX.test(value) && HASH_TYPE_BY_LENGTH[value.length]) {
    return { kind: "hash", value: value.toLowerCase() };
  }
  const ip = value.includes(":")
    ? validateIndicatorValue("ipv6", value)
    : validateIndicatorValue("ipv4", value);
  if (ip === null) return { kind: "ip", value: value.toLowerCase() };
  // A real top-level domain is never all digits, so "198.51" or "1.2.3.400" is not offered as a domain.
  const topLevel = value.slice(value.lastIndexOf(".") + 1);
  if (!/^\d+$/.test(topLevel) && validateIndicatorValue("domain", value) === null) {
    return { kind: "domain", value: value.toLowerCase() };
  }
  return null;
}

function failure(kind: IntelKind, raw: string, error: string): TargetResult {
  const detected = detectKind(raw);
  const suggestion =
    detected && detected.kind !== kind && detected.kind !== "cve"
      ? { kind: detected.kind, value: detected.value }
      : null;
  return { ok: false, error, suggestion };
}

/** Validates and canonicalizes what the user typed for the given kind of lookup. */
export function parseTarget(kind: IntelKind, raw: string): TargetResult {
  const value = raw.trim();
  if (!value) return { ok: false, error: "Enter a value to look up.", suggestion: null };
  if (value.length > MAX_TARGET_LENGTH) {
    return { ok: false, error: "That value is too long to look up.", suggestion: null };
  }

  switch (kind) {
    case "ip": {
      const indicatorType = value.includes(":") ? "ipv6" : "ipv4";
      if (validateIndicatorValue(indicatorType, value) !== null)
        return failure(kind, raw, IP_ERROR);
      return {
        ok: true,
        target: {
          kind,
          value: canonicalizeIndicatorValue(indicatorType, value),
          version: indicatorType === "ipv6" ? 6 : 4,
          indicatorType,
        },
      };
    }
    case "domain": {
      const problem = validateIndicatorValue("domain", value);
      if (problem) return failure(kind, raw, problem);
      return {
        ok: true,
        target: {
          kind,
          value: canonicalizeIndicatorValue("domain", value),
          indicatorType: "domain",
        },
      };
    }
    case "url": {
      const problem = validateIndicatorValue("url", value);
      if (problem) return failure(kind, raw, problem);
      let parsed: URL;
      try {
        parsed = new URL(value);
      } catch {
        return failure(kind, raw, "Enter a full http or https URL without spaces.");
      }
      return {
        ok: true,
        target: {
          kind,
          value,
          host: parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase(),
          hasCredentials: parsed.username !== "" || parsed.password !== "",
          indicatorType: "url",
        },
      };
    }
    case "hash": {
      const hashType = HEX.test(value) ? HASH_TYPE_BY_LENGTH[value.length] : undefined;
      if (!hashType) return failure(kind, raw, HASH_ERROR);
      return {
        ok: true,
        target: { kind, value: value.toLowerCase(), hashType, indicatorType: hashType },
      };
    }
  }
}

// ---------------------------------------------------------------------------------------------
// What may be sent to an external provider
// ---------------------------------------------------------------------------------------------

function ipv4Octets(ip: string): number[] | null {
  const parts = ip.split(".").map(Number);
  return parts.length === 4 &&
    parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts
    : null;
}

/** IPv4 ranges that are not routable on the public Internet (private, loopback, documentation, ...). */
export function isPublicIpv4(ip: string): boolean {
  const octets = ipv4Octets(ip);
  if (!octets) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false; // IETF protocol, documentation
  if (a === 192 && b === 88 && c === 99) return false; // 6to4 relay
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // documentation
  if (a === 203 && b === 0 && c === 113) return false; // documentation
  return true;
}

/** Expands an IPv6 address to its eight 16-bit groups, or null when it is malformed. */
export function ipv6Groups(ip: string): number[] | null {
  let text = ip.toLowerCase();
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);

  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted) {
    const octets = ipv4Octets(dotted[1]);
    if (!octets) return null;
    text =
      text.slice(0, -dotted[1].length) +
      ((octets[0] << 8) | octets[1]).toString(16) +
      ":" +
      ((octets[2] << 8) | octets[3]).toString(16);
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;

  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  const numbers = groups.map((group) =>
    /^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : NaN,
  );
  return numbers.length === 8 && numbers.every((n) => !Number.isNaN(n)) ? numbers : null;
}

/** Global unicast IPv6 (2000::/3) minus documentation and transition ranges. Anything unclear is not public. */
export function isPublicIpv6(ip: string): boolean {
  const groups = ipv6Groups(ip);
  if (!groups) return false;
  const [first, second] = groups;
  if (first < 0x2000 || first > 0x3fff) return false;
  if (first === 0x2001 && (second === 0x0db8 || second === 0x0000)) return false; // documentation, Teredo
  if (first === 0x2002) return false; // 6to4
  if (first === 0x3fff && second <= 0x0fff) return false; // documentation (RFC 9637)
  return true;
}

const RESERVED_SUFFIXES = new Set([
  "example",
  "test",
  "invalid",
  "localhost",
  "local",
  "internal",
  "lan",
  "home",
  "corp",
  "intranet",
  "localdomain",
  "arpa",
  "onion",
]);
const RESERVED_DOMAINS = ["example.com", "example.net", "example.org"];

/** Names that cannot exist on the public DNS (reserved TLDs, IANA example domains and their subdomains). */
export function isReservedHostname(host: string): boolean {
  const name = host.toLowerCase();
  const suffix = name.slice(name.lastIndexOf(".") + 1);
  return (
    RESERVED_SUFFIXES.has(suffix) ||
    RESERVED_DOMAINS.some((reserved) => name === reserved || name.endsWith(`.${reserved}`))
  );
}

function isPublicHost(host: string): boolean {
  if (z.ipv4().safeParse(host).success) return isPublicIpv4(host);
  if (host.includes(":") && z.ipv6().safeParse(host).success) return isPublicIpv6(host);
  return !isReservedHostname(host);
}

/**
 * Why this target must not be sent to an external provider, or null when it may be. Private,
 * reserved and documentation addresses and names are never sent (they would only leak internal
 * addressing), and neither are URLs that carry a user name or password.
 */
export function externalSkipReason(
  target: IntelTarget,
): Exclude<SkipReason, "not_permitted"> | null {
  switch (target.kind) {
    case "ip":
      return (target.version === 4 ? isPublicIpv4(target.value) : isPublicIpv6(target.value))
        ? null
        : "not_public";
    case "domain":
      return isReservedHostname(target.value) ? "not_public" : null;
    case "url":
      if (target.hasCredentials) return "has_credentials";
      return isPublicHost(target.host) ? null : "not_public";
    case "hash":
      return null;
  }
}
