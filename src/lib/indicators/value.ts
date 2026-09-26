import { z } from "zod";
import type { IndicatorType } from "@/types/domain";

/**
 * Structural checks for an indicator value, mirroring `public.is_valid_indicator` in the database
 * (migration 20260925100200), which stays the authority. This copy exists to give a helpful message
 * before the request is sent, and on the server before the database has to refuse it. A value that
 * passes is well-formed, not malicious.
 */
const HEX = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };
const CVE = /^CVE-[0-9]{4}-[0-9]{4,}$/i;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/i;
const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;
const URL_HTTP = /^https?:\/\/[^\s/?#]+([/?#]\S*)?$/i;

export const VALUE_HINTS: Record<IndicatorType, { placeholder: string; error: string }> = {
  ipv4: { placeholder: "203.0.113.10", error: "Enter a valid IPv4 address, such as 203.0.113.10." },
  ipv6: {
    placeholder: "2001:db8::1",
    error: "Enter a valid IPv6 address without a prefix length, such as 2001:db8::1.",
  },
  domain: {
    placeholder: "malicious.example",
    error: "Enter a domain name such as malicious.example (no scheme, path or trailing dot).",
  },
  url: {
    placeholder: "https://malicious.example/login",
    error: "Enter a full http or https URL without spaces.",
  },
  md5: {
    placeholder: "32 hexadecimal characters",
    error: "An MD5 hash has 32 hexadecimal characters.",
  },
  sha1: {
    placeholder: "40 hexadecimal characters",
    error: "A SHA-1 hash has 40 hexadecimal characters.",
  },
  sha256: {
    placeholder: "64 hexadecimal characters",
    error: "A SHA-256 hash has 64 hexadecimal characters.",
  },
  email: { placeholder: "sender@malicious.example", error: "Enter a valid email address." },
  cve: { placeholder: "CVE-2021-44228", error: "Enter a CVE id such as CVE-2021-44228." },
  other: { placeholder: "Any identifier", error: "Enter a value." },
};

/** Returns an error message, or null when `value` is a well-formed `type`. Expects a trimmed value. */
export function validateIndicatorValue(type: IndicatorType, value: string): string | null {
  const ok = (() => {
    switch (type) {
      case "ipv4":
        return z.ipv4().safeParse(value).success;
      case "ipv6":
        return value.includes(":") && !value.includes("/") && z.ipv6().safeParse(value).success;
      case "md5":
      case "sha1":
      case "sha256":
        return HEX[type].test(value);
      case "cve":
        return CVE.test(value);
      case "email":
        return EMAIL.test(value);
      case "domain":
        return value.length <= 253 && DOMAIN.test(value);
      case "url":
        return URL_HTTP.test(value);
      case "other":
        return value.length > 0;
    }
  })();
  return ok ? null : VALUE_HINTS[type].error;
}

/** How a value is stored: hosts and hashes lower-case, CVE ids upper-case, URLs untouched. */
export function canonicalizeIndicatorValue(type: IndicatorType, value: string): string {
  switch (type) {
    case "cve":
      return value.toUpperCase();
    case "url":
    case "other":
      return value;
    default:
      return value.toLowerCase();
  }
}

/** Mirror of the `value_normalized` generated column: the key duplicates are detected on. */
export function normalizeIndicatorValue(type: IndicatorType, value: string): string {
  if (type === "cve") return value.toUpperCase();
  if (type === "url") return value;
  return value.toLowerCase();
}
