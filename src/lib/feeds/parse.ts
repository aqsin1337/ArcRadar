import type { ExternalIndicatorRecord } from "@/lib/indicators/external";
import { validateIndicatorValue } from "@/lib/indicators/value";
import { isPublicIpv4, isPublicIpv6 } from "@/lib/intel/target";
import type { IndicatorType } from "@/types/domain";

/*
 * Turning what a public threat feed publishes into indicator records. Pure functions: no network, no
 * database, no clock except the one passed in, so every rule is testable. A feed is a list of things
 * somebody else has already judged malicious, so these records carry verdict "malicious" with the
 * feed's own confidence; the description always says which feed said so. Nothing is ever fetched
 * from the addresses in a feed, and an entry the database would refuse is dropped here or there.
 */

/** How many entries one feed may contribute per import (newest first): the list stays readable. */
export const MAX_ENTRIES_PER_FEED = 300;

const MAX_URL_LENGTH = 2000;

const parseUtc = (value: unknown): string | null => {
  if (typeof value !== "string" || value.trim() === "") return null;
  // "2026-03-07" and "2026-03-07 21:24:53" are UTC; anything else goes to Date as it is.
  const text = value.trim();
  const iso = /^\d{4}-\d{2}-\d{2}$/.test(text)
    ? `${text}T00:00:00Z`
    : /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text)
      ? `${text.replace(" ", "T")}Z`
      : text;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

function isPublicAddress(ip: string): boolean {
  return ip.includes(":") ? isPublicIpv6(ip) : isPublicIpv4(ip);
}

function feedUrl(raw: string): string | null {
  const value = raw.trim();
  if (value.length === 0 || value.length > MAX_URL_LENGTH) return null;
  if (!/^https?:\/\//i.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.username || url.password) return null; // never store credentials
  } catch {
    return null;
  }
  return validateIndicatorValue("url", value) === null ? value : null;
}

/** abuse.ch URLhaus, "recent" plain-text list: one malware distribution URL per line, `#` comments. */
export function parseUrlhausText(text: string, now: Date): ExternalIndicatorRecord[] {
  const records: ExternalIndicatorRecord[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    if (records.length >= MAX_ENTRIES_PER_FEED) break;
    if (line.startsWith("#")) continue;
    const value = feedUrl(line);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    records.push({
      type: "url",
      value,
      verdict: "malicious",
      severity: "high",
      confidence: 85,
      description: "Listed in the abuse.ch URLhaus feed of recently reported malware URLs.",
      seen_at: now.toISOString(),
    });
  }
  return records;
}

type FeodoEntry = {
  ip_address?: unknown;
  port?: unknown;
  status?: unknown;
  malware?: unknown;
  first_seen?: unknown;
  last_online?: unknown;
};

/** abuse.ch Feodo Tracker botnet C2 blocklist (JSON array). */
export function parseFeodoJson(body: unknown, now: Date): ExternalIndicatorRecord[] {
  if (!Array.isArray(body)) return [];
  const records: ExternalIndicatorRecord[] = [];
  const seen = new Set<string>();
  for (const entry of body as FeodoEntry[]) {
    if (records.length >= MAX_ENTRIES_PER_FEED) break;
    const ip = typeof entry?.ip_address === "string" ? entry.ip_address.trim().toLowerCase() : "";
    if (!ip || seen.has(ip) || !isPublicAddress(ip)) continue;
    seen.add(ip);
    const family = typeof entry.malware === "string" && entry.malware ? entry.malware : "botnet";
    const port = typeof entry.port === "number" ? `, port ${entry.port}` : "";
    const status = entry.status === "online" ? "online" : "offline";
    records.push({
      type: ip.includes(":") ? "ipv6" : "ipv4",
      value: ip,
      verdict: "malicious",
      severity: "high",
      confidence: entry.status === "online" ? 95 : 80,
      description: `Listed by abuse.ch Feodo Tracker as a ${family} command-and-control server${port} (${status}).`,
      seen_at: parseUtc(entry.last_online) ?? parseUtc(entry.first_seen) ?? now.toISOString(),
    });
  }
  return records;
}

type ThreatFoxEntry = {
  ioc_value?: unknown;
  ioc_type?: unknown;
  threat_type?: unknown;
  malware_printable?: unknown;
  confidence_level?: unknown;
  first_seen_utc?: unknown;
  last_seen_utc?: unknown;
};

const THREATFOX_TYPES: Record<string, IndicatorType> = {
  domain: "domain",
  url: "url",
  sha256_hash: "sha256",
  sha1_hash: "sha1",
  md5_hash: "md5",
};

/** Only entries the feed itself is fairly sure about. */
export const THREATFOX_MIN_CONFIDENCE = 75;

/**
 * abuse.ch ThreatFox export, "recent": an object of id -> [entries] (an array of entries is accepted
 * too). `ip:port` entries become the address alone.
 */
export function parseThreatFoxJson(body: unknown, now: Date): ExternalIndicatorRecord[] {
  let entries: ThreatFoxEntry[] = [];
  if (Array.isArray(body)) {
    entries = body.flat() as ThreatFoxEntry[];
  } else if (body && typeof body === "object") {
    entries = Object.values(body as Record<string, unknown>).flatMap((value) =>
      Array.isArray(value) ? (value as ThreatFoxEntry[]) : [],
    );
  }

  const candidates: { record: ExternalIndicatorRecord; first: number }[] = [];
  for (const entry of entries) {
    const raw = typeof entry?.ioc_value === "string" ? entry.ioc_value.trim() : "";
    const kind = typeof entry?.ioc_type === "string" ? entry.ioc_type : "";
    const confidence = typeof entry.confidence_level === "number" ? entry.confidence_level : 0;
    if (!raw || confidence < THREATFOX_MIN_CONFIDENCE) continue;

    let type: IndicatorType | undefined;
    let value = raw;
    if (kind === "ip:port") {
      const host = raw.startsWith("[") ? raw.slice(1, raw.indexOf("]")) : raw.replace(/:\d+$/, "");
      if (!isPublicAddress(host.toLowerCase())) continue;
      value = host.toLowerCase();
      type = value.includes(":") ? "ipv6" : "ipv4";
    } else {
      type = THREATFOX_TYPES[kind];
      if (!type) continue;
      if (type === "url") {
        const url = feedUrl(raw);
        if (!url) continue;
        value = url;
      } else {
        value = raw.toLowerCase();
        if (validateIndicatorValue(type, value) !== null) continue;
      }
    }

    const family =
      typeof entry.malware_printable === "string" && entry.malware_printable
        ? entry.malware_printable
        : "unknown malware";
    const threat =
      typeof entry.threat_type === "string" ? entry.threat_type.replace(/_/g, " ") : "";
    const firstSeen = parseUtc(entry.first_seen_utc);
    candidates.push({
      record: {
        type,
        value,
        verdict: "malicious",
        severity: "high",
        confidence: Math.min(100, Math.round(confidence)),
        description: `Listed by abuse.ch ThreatFox: ${family}${threat ? ` (${threat})` : ""}, feed confidence ${confidence}.`,
        seen_at: parseUtc(entry.last_seen_utc) ?? firstSeen ?? now.toISOString(),
      },
      first: firstSeen ? Date.parse(firstSeen) : 0,
    });
  }

  const seen = new Set<string>();
  return candidates
    .sort((a, b) => b.first - a.first)
    .map(({ record }) => record)
    .filter((record) => {
      const key = `${record.type}:${record.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_ENTRIES_PER_FEED);
}
