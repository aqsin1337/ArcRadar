import { z } from "zod";
import { validateIndicatorValue } from "@/lib/indicators/value";
import { ipv6Groups, isPublicIpv4, isPublicIpv6, isReservedHostname } from "@/lib/intel/target";
import type { IndicatorType } from "@/types/domain";
import { MAX_INDICATORS_PER_ALERT } from "./constants";

/*
 * Which values of a sensor's alert are worth tracking as indicators. Only what could identify
 * something outside the machine: a public address, a hash, a real domain or URL. Private addresses,
 * loopback, internal names and the like are the sensor's own network, never an indicator. Addresses
 * from the documentation ranges are kept (a lab simulates attacks from them; nothing is ever looked
 * up automatically). Nothing here says a value is malicious: the database records these as unknown.
 */

export type IndicatorCandidate = { type: IndicatorType; value: string };

const IPV4 = z.ipv4();
const IPV6 = z.ipv6();

function isDocumentationIpv4(ip: string): boolean {
  return /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(ip);
}

/** A public address, or a documentation one (see above). */
export function isTrackableIp(ip: string): boolean {
  if (IPV4.safeParse(ip).success) return isPublicIpv4(ip) || isDocumentationIpv4(ip);
  if (ip.includes(":") && IPV6.safeParse(ip).success) {
    const groups = ipv6Groups(ip);
    const documentation = groups !== null && groups[0] === 0x2001 && groups[1] === 0x0db8;
    return isPublicIpv6(ip) || documentation;
  }
  return false;
}

const INTERNAL_SUFFIXES = new Set([
  "local",
  "lan",
  "internal",
  "home",
  "corp",
  "intranet",
  "localdomain",
  "localhost",
  "arpa",
  "onion",
]);

export function isTrackableDomain(name: string): boolean {
  const host = name.toLowerCase().replace(/\.$/, "");
  if (validateIndicatorValue("domain", host) !== null) return false;
  const suffix = host.slice(host.lastIndexOf(".") + 1);
  if (/^\d+$/.test(suffix) || INTERNAL_SUFFIXES.has(suffix)) return false;
  // The IANA example names are documentation, like the addresses above: fine in a lab.
  return !isReservedHostname(host) || /(^|\.)example(\.(com|net|org))?$/.test(host);
}

function at(source: unknown, path: readonly string[]): unknown {
  let current: unknown = source;
  for (const key of path) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : null;

/** Sysmon writes "SHA1=...,MD5=...,SHA256=...,IMPHASH=..."; pull out the digest of one algorithm. */
function digestFrom(hashes: string | null, algorithm: "SHA256" | "SHA1" | "MD5"): string | null {
  if (!hashes) return null;
  const match = new RegExp(`(?:^|[,\\s])${algorithm}=([a-f0-9]+)`, "i").exec(hashes);
  return match ? match[1].toLowerCase() : null;
}

const isDigest = (value: string, length: 32 | 40 | 64) =>
  value.length === length && /^[a-f0-9]+$/i.test(value);

/**
 * The indicators of an alert in the order they matter for an alert's single indicator link: where
 * the traffic went, where the attack came from, the file, then the name and the address that were
 * looked up. At most `MAX_INDICATORS_PER_ALERT`, no duplicates.
 */
export function extractIndicators(alert: Record<string, unknown>): IndicatorCandidate[] {
  const data = alert.data;
  const eventdata = at(data, ["win", "eventdata"]);
  const found: IndicatorCandidate[] = [];
  const add = (type: IndicatorType, raw: string | null) => {
    if (!raw) return;
    const value = type === "url" ? raw : raw.toLowerCase();
    if (validateIndicatorValue(type, value) !== null) return;
    if (found.some((candidate) => candidate.type === type && candidate.value === value)) return;
    found.push({ type, value });
  };
  const ip = (raw: string | null) => {
    if (raw && isTrackableIp(raw)) add(raw.includes(":") ? "ipv6" : "ipv4", raw);
  };

  // 1. where it went, 2. where it came from
  for (const path of [["destinationIp"], ["dstip"], ["dst_ip"]]) {
    ip(text(at(eventdata, path)) ?? text(at(data, path)));
  }
  for (const path of [["ipAddress"], ["sourceIp"], ["srcip"], ["src_ip"]]) {
    ip(text(at(eventdata, path)) ?? text(at(data, path)));
  }

  // 3. the file: SHA-256 first, then the weaker digests
  const hashes = text(at(eventdata, ["hashes"]));
  const syscheck = at(alert, ["syscheck"]);
  const sha256 =
    digestFrom(hashes, "SHA256") ??
    text(at(syscheck, ["sha256_after"])) ??
    text(at(data, ["sha256"]));
  if (sha256 && isDigest(sha256, 64)) add("sha256", sha256);
  const sha1 =
    digestFrom(hashes, "SHA1") ?? text(at(syscheck, ["sha1_after"])) ?? text(at(data, ["sha1"]));
  if (sha1 && isDigest(sha1, 40)) add("sha1", sha1);
  const md5 =
    digestFrom(hashes, "MD5") ?? text(at(syscheck, ["md5_after"])) ?? text(at(data, ["md5"]));
  if (md5 && isDigest(md5, 32)) add("md5", md5);

  // 4. a name that was looked up (Sysmon DNS query), 5. a full URL
  const query = text(at(eventdata, ["queryName"]));
  if (query && isTrackableDomain(query)) add("domain", query.replace(/\.$/, ""));
  const url = text(at(data, ["url"]));
  if (url && /^https?:\/\//i.test(url)) add("url", url);

  return found.slice(0, MAX_INDICATORS_PER_ALERT);
}
