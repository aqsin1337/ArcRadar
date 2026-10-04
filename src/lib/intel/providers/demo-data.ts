import { createHash } from "node:crypto";
import type {
  Detections,
  DomainProfile,
  EngineFinding,
  HashProfile,
  HashType,
  IpProfile,
  Reputation,
  UrlProfile,
} from "../types";

/*
 * The demo provider's dataset. Everything here is SAMPLE data for demonstration, never live
 * intelligence, and the UI labels it as such:
 *  - the fictional scenario uses RFC 5737 / RFC 3849 documentation addresses, reserved TLDs
 *    (.example, .test), documentation AS numbers (RFC 5398) and invented organisations, engines and
 *    malware families, exactly like supabase/seed.sql, so it lines up with the seeded indicators;
 *  - fictional infrastructure has no country or city: no real-world location or attribution is
 *    invented;
 *  - three real, harmless subjects show what a clean result looks like: the Google public DNS
 *    resolver 8.8.8.8, the IANA reserved example.com, and the EICAR antivirus test file.
 */

const DAY_MS = 86_400_000;
const daysAgo = (now: Date, days: number) => new Date(now.getTime() - days * DAY_MS).toISOString();

const detections = (
  malicious: number,
  suspicious: number,
  harmless: number,
  undetected: number,
): Detections => ({ malicious, suspicious, harmless, undetected });

const ENGINES = ["Demo Engine Alpha", "Demo Engine Beta", "Demo Engine Gamma", "Demo Engine Delta"];
const findings = (category: "malicious" | "suspicious", ...results: string[]): EngineFinding[] =>
  results.map((result, index) => ({ engine: ENGINES[index % ENGINES.length], category, result }));

const malicious = (confidence: number, summary: string): Reputation => ({
  verdict: "malicious",
  confidence,
  summary,
});
const suspicious = (confidence: number, summary: string): Reputation => ({
  verdict: "suspicious",
  confidence,
  summary,
});
const benign = (confidence: number, summary: string): Reputation => ({
  verdict: "benign",
  confidence,
  summary,
});

// --- IP addresses ---------------------------------------------------------------------------------

type IpSpec = Pick<IpProfile, "reputation" | "detections" | "findings" | "tags"> &
  Partial<
    Pick<
      IpProfile,
      | "network"
      | "asn"
      | "organization"
      | "isp"
      | "usage_type"
      | "country"
      | "region"
      | "city"
      | "hostnames"
      | "open_ports"
      | "related_domains"
      | "report_count"
    >
  > & { reportedDaysAgo?: number; analysedDaysAgo?: number };

const HARBOR = {
  asn: 64501,
  organization: "Harbor Demo Hosting (fictional)",
  isp: "Harbor Demo Hosting (fictional)",
  usage_type: "Data Center/Web Hosting/Transit",
};
const LANTERN = {
  asn: 64502,
  organization: "Lantern Demo Networks (fictional)",
  isp: "Lantern Demo Networks (fictional)",
  usage_type: "Data Center/Web Hosting/Transit",
};

const IP_SPECS: Record<string, IpSpec> = {
  "198.51.100.23": {
    ...HARBOR,
    network: "198.51.100.0/24",
    hostnames: ["gate.harbor-lights-c2.example"],
    open_ports: [80, 443, 8443],
    related_domains: ["harbor-lights-c2.example"],
    report_count: 214,
    reportedDaysAgo: 1,
    analysedDaysAgo: 1,
    reputation: malicious(
      92,
      "Command-and-control server in the fictional Harbor Lights scenario.",
    ),
    detections: detections(17, 4, 52, 14),
    findings: findings("malicious", "C2 server", "Malware distribution", "Botnet C2", "C2 server"),
    tags: ["c2", "harbor-lights"],
  },
  "198.51.100.77": {
    ...HARBOR,
    network: "198.51.100.0/24",
    open_ports: [443, 1194],
    related_domains: ["login-secure-update.example"],
    report_count: 96,
    reportedDaysAgo: 1,
    analysedDaysAgo: 2,
    reputation: malicious(85, "Source of credential-stuffing attempts against VPN portals."),
    detections: detections(11, 5, 58, 18),
    findings: findings("malicious", "Brute force", "Credential stuffing", "Phishing"),
    tags: ["credential-stuffing", "vpn"],
  },
  "203.0.113.45": {
    ...LANTERN,
    network: "203.0.113.0/24",
    open_ports: [80, 443],
    report_count: 41,
    reportedDaysAgo: 3,
    analysedDaysAgo: 3,
    reputation: malicious(80, "Repeated web shell upload attempts."),
    detections: detections(9, 4, 61, 18),
    findings: findings("malicious", "Web attack", "Exploit attempt"),
    tags: ["webshell", "exploit"],
  },
  "203.0.113.9": {
    ...LANTERN,
    network: "203.0.113.0/24",
    open_ports: [22, 80],
    report_count: 23,
    reportedDaysAgo: 2,
    analysedDaysAgo: 2,
    reputation: suspicious(60, "Broad port scanning activity."),
    detections: detections(2, 6, 64, 20),
    findings: findings("suspicious", "Port scan", "Scanner"),
    tags: ["scanning"],
  },
  "192.0.2.150": {
    asn: 64503,
    organization: "Relay Demo Transit (fictional)",
    isp: "Relay Demo Transit (fictional)",
    usage_type: "Tor exit relay",
    network: "192.0.2.128/25",
    open_ports: [443, 9001],
    report_count: 12,
    reportedDaysAgo: 4,
    analysedDaysAgo: 4,
    reputation: suspicious(
      55,
      "Traffic comes from a Tor exit relay. Tor is legitimate; treat with context.",
    ),
    detections: detections(0, 5, 66, 21),
    findings: findings("suspicious", "Anonymizer"),
    tags: ["tor-exit"],
  },
  "192.0.2.10": {
    asn: 64504,
    organization: "Example Corp Internal (fictional)",
    isp: "Example Corp Internal (fictional)",
    usage_type: "Corporate network",
    network: "192.0.2.0/25",
    report_count: 0,
    analysedDaysAgo: 1,
    reputation: benign(90, "The organisation's own vulnerability scanner; allow-listed."),
    detections: detections(0, 0, 70, 22),
    findings: [],
    tags: ["internal", "scanner"],
  },
  "198.51.100.200": {
    ...HARBOR,
    network: "198.51.100.128/25",
    open_ports: [80, 443],
    related_domains: ["invoice-download.example"],
    report_count: 58,
    reportedDaysAgo: 6,
    analysedDaysAgo: 6,
    reputation: malicious(70, "Hosts a malware download site."),
    detections: detections(8, 3, 60, 21),
    findings: findings("malicious", "Malware distribution", "Malicious download"),
    tags: ["malware-distribution"],
  },
  "192.0.2.66": {
    ...LANTERN,
    network: "192.0.2.64/26",
    open_ports: [443, 8080],
    report_count: 77,
    reportedDaysAgo: 2,
    analysedDaysAgo: 2,
    reputation: malicious(88, "Beacon check-ins at a regular interval."),
    detections: detections(14, 3, 55, 20),
    findings: findings("malicious", "C2 beaconing", "Botnet C2", "C2 beaconing"),
    tags: ["c2", "beaconing"],
  },
  "2001:db8:bad:1::5": {
    ...HARBOR,
    network: "2001:db8:bad:1::/64",
    open_ports: [443],
    report_count: 19,
    reportedDaysAgo: 2,
    analysedDaysAgo: 2,
    reputation: malicious(75, "Command-and-control endpoint reachable over IPv6."),
    detections: detections(7, 2, 62, 21),
    findings: findings("malicious", "C2 server", "Botnet C2"),
    tags: ["c2", "ipv6"],
  },
  "8.8.8.8": {
    asn: 15169,
    organization: "Google LLC",
    isp: "Google LLC",
    usage_type: "Public DNS resolver",
    country: "United States",
    region: "California",
    city: "Mountain View",
    network: "8.8.8.0/24",
    hostnames: ["dns.google"],
    open_ports: [53, 443, 853],
    related_domains: ["dns.google"],
    report_count: 0,
    analysedDaysAgo: 1,
    reputation: benign(95, "A well-known public DNS resolver operated by Google (sample record)."),
    detections: detections(0, 0, 68, 24),
    findings: [],
    tags: ["public-dns"],
  },
};

export function demoIpProfile(ip: string, now: Date): IpProfile | null {
  const spec = IP_SPECS[ip];
  if (!spec) return null;
  return {
    kind: "ip",
    ip,
    version: ip.includes(":") ? 6 : 4,
    network: spec.network ?? null,
    asn: spec.asn ?? null,
    organization: spec.organization ?? null,
    isp: spec.isp ?? null,
    usage_type: spec.usage_type ?? null,
    country: spec.country ?? null,
    region: spec.region ?? null,
    city: spec.city ?? null,
    hostnames: spec.hostnames ?? [],
    open_ports: spec.open_ports ?? [],
    related_domains: spec.related_domains ?? [],
    report_count: spec.report_count ?? null,
    last_reported_at:
      spec.reportedDaysAgo === undefined ? null : daysAgo(now, spec.reportedDaysAgo),
    retrieved_at: now.toISOString(),
    reputation: spec.reputation,
    detections: spec.detections,
    findings: spec.findings,
    tags: spec.tags,
    last_analysed_at:
      spec.analysedDaysAgo === undefined ? null : daysAgo(now, spec.analysedDaysAgo),
  };
}

// --- Domains ---------------------------------------------------------------------------------------

type DomainSpec = Pick<DomainProfile, "reputation" | "detections" | "findings" | "tags"> &
  Partial<
    Pick<DomainProfile, "registrar" | "nameservers" | "dns_records" | "related_ips" | "categories">
  > & { createdDaysAgo?: number | string; expiresInDays?: number; analysedDaysAgo?: number };

const DEMO_REGISTRAR = "Example Registrar Ltd (fictional)";
const DEMO_NS = ["ns1.demo-dns.example", "ns2.demo-dns.example"];

const DOMAIN_SPECS: Record<string, DomainSpec> = {
  "harbor-lights-c2.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 41,
    expiresInDays: 324,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "A", value: "198.51.100.23", ttl: 300 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
      { type: "NS", value: DEMO_NS[1], ttl: 3600 },
    ],
    related_ips: ["198.51.100.23"],
    categories: ["command and control"],
    analysedDaysAgo: 1,
    reputation: malicious(
      95,
      "Command-and-control domain in the fictional Harbor Lights scenario.",
    ),
    detections: detections(19, 3, 50, 14),
    findings: findings("malicious", "C2 domain", "Malware distribution", "C2 domain"),
    tags: ["c2", "harbor-lights"],
  },
  "login-secure-update.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 31,
    expiresInDays: 334,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "A", value: "198.51.100.77", ttl: 300 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
      { type: "NS", value: DEMO_NS[1], ttl: 3600 },
    ],
    related_ips: ["198.51.100.77"],
    categories: ["phishing"],
    analysedDaysAgo: 1,
    reputation: malicious(90, "Credential-harvesting page impersonating a sign-in portal."),
    detections: detections(15, 5, 54, 14),
    findings: findings("malicious", "Phishing", "Credential harvesting", "Phishing"),
    tags: ["phishing", "credential-theft"],
  },
  "paper-lantern-mail.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 57,
    expiresInDays: 308,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "A", value: "203.0.113.88", ttl: 300 },
      { type: "MX", value: "mail.paper-lantern-mail.example", ttl: 300 },
      { type: "TXT", value: "v=spf1 -all", ttl: 300 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
    ],
    related_ips: ["203.0.113.88"],
    categories: ["phishing", "spam"],
    analysedDaysAgo: 1,
    reputation: malicious(93, "Sender domain of the fictional Paper Lantern phishing wave."),
    detections: detections(21, 4, 47, 14),
    findings: findings("malicious", "Phishing", "Spam sender", "Phishing"),
    tags: ["phishing", "apt"],
  },
  "invoice-download.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 22,
    expiresInDays: 343,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "A", value: "198.51.100.200", ttl: 300 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
    ],
    related_ips: ["198.51.100.200"],
    categories: ["malware distribution"],
    analysedDaysAgo: 2,
    reputation: malicious(78, "Serves malicious invoice archives."),
    detections: detections(10, 4, 58, 20),
    findings: findings("malicious", "Malware distribution", "Malicious download"),
    tags: ["malware-distribution", "phishing"],
  },
  "cdn-assets-delivery.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 14,
    expiresInDays: 351,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "A", value: "203.0.113.120", ttl: 60 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
    ],
    related_ips: ["203.0.113.120"],
    categories: ["newly registered"],
    analysedDaysAgo: 2,
    reputation: suspicious(60, "Newly registered domain serving obfuscated scripts."),
    detections: detections(1, 6, 62, 21),
    findings: findings("suspicious", "Suspicious script host", "Newly registered domain"),
    tags: ["newly-registered"],
  },
  "static.trusted-cdn.example": {
    registrar: DEMO_REGISTRAR,
    createdDaysAgo: 2400,
    expiresInDays: 250,
    nameservers: DEMO_NS,
    dns_records: [
      { type: "CNAME", value: "edge.trusted-cdn.example", ttl: 300 },
      { type: "NS", value: DEMO_NS[0], ttl: 3600 },
    ],
    categories: ["content delivery"],
    analysedDaysAgo: 1,
    reputation: benign(85, "The organisation's approved content-delivery domain."),
    detections: detections(0, 0, 71, 21),
    findings: [],
    tags: ["internal"],
  },
  "example.com": {
    registrar: "RESERVED-Internet Assigned Numbers Authority",
    createdDaysAgo: "1995-08-14T04:00:00.000Z",
    nameservers: ["a.iana-servers.net", "b.iana-servers.net"],
    dns_records: [
      { type: "NS", value: "a.iana-servers.net", ttl: null },
      { type: "NS", value: "b.iana-servers.net", ttl: null },
    ],
    categories: ["reserved for documentation"],
    analysedDaysAgo: 1,
    reputation: benign(90, "Reserved by IANA for use in documentation (sample record)."),
    detections: detections(0, 0, 70, 22),
    findings: [],
    tags: ["iana-reserved"],
  },
};

export function demoDomainProfile(domain: string, now: Date): DomainProfile | null {
  const spec = DOMAIN_SPECS[domain];
  if (!spec) return null;
  const created =
    spec.createdDaysAgo === undefined
      ? null
      : typeof spec.createdDaysAgo === "string"
        ? spec.createdDaysAgo
        : daysAgo(now, spec.createdDaysAgo);
  return {
    kind: "domain",
    domain,
    registrar: spec.registrar ?? null,
    created_at: created,
    updated_at: null,
    expires_at: spec.expiresInDays === undefined ? null : daysAgo(now, -spec.expiresInDays),
    nameservers: spec.nameservers ?? [],
    dns_records: spec.dns_records ?? [],
    related_ips: spec.related_ips ?? [],
    categories: spec.categories ?? [],
    retrieved_at: now.toISOString(),
    reputation: spec.reputation,
    detections: spec.detections,
    findings: spec.findings,
    tags: spec.tags,
    last_analysed_at:
      spec.analysedDaysAgo === undefined ? null : daysAgo(now, spec.analysedDaysAgo),
  };
}

// --- URLs -------------------------------------------------------------------------------------------

type UrlSpec = Pick<UrlProfile, "reputation" | "detections" | "findings" | "tags"> &
  Partial<
    Pick<UrlProfile, "final_url" | "redirect_chain" | "http_status" | "title" | "categories">
  > & {
    firstSubmittedDaysAgo?: number;
    analysedDaysAgo?: number;
  };

const URL_SPECS: Record<string, UrlSpec> = {
  "https://login-secure-update.example/account/verify?session=demo": {
    final_url: "https://login-secure-update.example/account/verify?session=demo",
    http_status: 200,
    title: "Verify your account",
    categories: ["phishing"],
    firstSubmittedDaysAgo: 29,
    analysedDaysAgo: 1,
    reputation: malicious(88, "Phishing landing page that imitates a sign-in form."),
    detections: detections(16, 4, 52, 16),
    findings: findings("malicious", "Phishing", "Credential harvesting", "Phishing"),
    tags: ["phishing"],
  },
  "http://invoice-download.example/files/invoice_2026.zip": {
    final_url: "https://invoice-download.example/dl/invoice_2026.zip",
    redirect_chain: [
      "http://invoice-download.example/files/invoice_2026.zip",
      "https://invoice-download.example/dl/invoice_2026.zip",
    ],
    http_status: 200,
    categories: ["malware distribution"],
    firstSubmittedDaysAgo: 20,
    analysedDaysAgo: 2,
    reputation: malicious(84, "Serves an archive that contains a loader."),
    detections: detections(13, 3, 55, 19),
    findings: findings("malicious", "Malicious download", "Malware distribution"),
    tags: ["malware-distribution"],
  },
  "https://paper-lantern-mail.example/track/open.gif": {
    final_url: "https://paper-lantern-mail.example/track/open.gif",
    http_status: 200,
    categories: ["tracking"],
    firstSubmittedDaysAgo: 50,
    analysedDaysAgo: 2,
    reputation: suspicious(62, "Tracking pixel from the fictional Paper Lantern phishing wave."),
    detections: detections(2, 5, 62, 21),
    findings: findings("suspicious", "Tracking pixel", "Phishing"),
    tags: ["phishing", "tracking"],
  },
  "http://198.51.100.23/gate.php": {
    final_url: "http://198.51.100.23/gate.php",
    http_status: 200,
    categories: ["command and control"],
    firstSubmittedDaysAgo: 38,
    analysedDaysAgo: 1,
    reputation: malicious(91, "Loader check-in endpoint in the fictional Harbor Lights scenario."),
    detections: detections(18, 3, 51, 14),
    findings: findings("malicious", "C2 endpoint", "Malware distribution", "C2 endpoint"),
    tags: ["c2"],
  },
  "https://harbor-lights-c2.example/api/v2/poll": {
    final_url: "https://harbor-lights-c2.example/api/v2/poll",
    http_status: 200,
    categories: ["command and control"],
    firstSubmittedDaysAgo: 39,
    analysedDaysAgo: 1,
    reputation: malicious(94, "Command polling endpoint in the fictional Harbor Lights scenario."),
    detections: detections(20, 3, 49, 14),
    findings: findings("malicious", "C2 endpoint", "Botnet C2", "C2 endpoint"),
    tags: ["c2", "harbor-lights"],
  },
  "https://cdn-assets-delivery.example/js/loader.min.js": {
    final_url: "https://cdn-assets-delivery.example/js/loader.min.js",
    http_status: 200,
    categories: ["suspicious script"],
    firstSubmittedDaysAgo: 13,
    analysedDaysAgo: 2,
    reputation: suspicious(58, "Obfuscated JavaScript loader."),
    detections: detections(1, 6, 63, 20),
    findings: findings("suspicious", "Obfuscated script", "Suspicious script"),
    tags: ["obfuscated"],
  },
};

export function demoUrlProfile(url: string, now: Date): UrlProfile | null {
  const spec = URL_SPECS[url];
  if (!spec) return null;
  return {
    kind: "url",
    url,
    host: new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase(),
    final_url: spec.final_url ?? null,
    redirect_chain: spec.redirect_chain ?? [],
    http_status: spec.http_status ?? null,
    title: spec.title ?? null,
    categories: spec.categories ?? [],
    first_submitted_at:
      spec.firstSubmittedDaysAgo === undefined ? null : daysAgo(now, spec.firstSubmittedDaysAgo),
    retrieved_at: now.toISOString(),
    reputation: spec.reputation,
    detections: spec.detections,
    findings: spec.findings,
    tags: spec.tags,
    last_analysed_at:
      spec.analysedDaysAgo === undefined ? null : daysAgo(now, spec.analysedDaysAgo),
  };
}

// --- File hashes ------------------------------------------------------------------------------------

type HashSpec = Pick<HashProfile, "reputation" | "detections" | "findings" | "tags"> &
  Partial<
    Pick<HashProfile, "malware_families" | "file_name" | "file_names" | "file_type" | "file_size">
  > & { firstSubmittedDaysAgo?: number; analysedDaysAgo?: number };

const digest = (algorithm: HashType, text: string) =>
  createHash(algorithm).update(text, "utf8").digest("hex");

/**
 * The seed's sample hashes are digests of made-up strings ("arcradar-demo-sample-N"), so all three
 * digest forms of one sample are known: looking up any of them finds the same sample.
 */
const SAMPLE_SPECS: [number, HashSpec][] = [
  [
    1,
    {
      malware_families: ["NightLoader"],
      file_name: "invoice_viewer.exe",
      file_type: "Win32 EXE",
      file_size: 1_482_752,
      firstSubmittedDaysAgo: 35,
      analysedDaysAgo: 1,
      reputation: malicious(94, "Loader dropper from the fictional Harbor Lights scenario."),
      detections: detections(41, 6, 17, 8),
      findings: findings("malicious", "Trojan.NightLoader", "Loader.Generic", "Trojan.NightLoader"),
      tags: ["loader", "peexe"],
    },
  ],
  [
    2,
    {
      malware_families: ["EmberLock"],
      file_name: "ember_update.exe",
      file_type: "Win32 EXE",
      file_size: 2_310_144,
      firstSubmittedDaysAgo: 42,
      analysedDaysAgo: 2,
      reputation: malicious(96, "Ransomware payload (fictional EmberLock family)."),
      detections: detections(52, 3, 9, 4),
      findings: findings("malicious", "Ransom.EmberLock", "Ransom.Generic", "Ransom.EmberLock"),
      tags: ["ransomware", "peexe"],
    },
  ],
  [
    3,
    {
      malware_families: ["QuietBeacon"],
      file_name: "svchost_helper.dll",
      file_type: "Win32 DLL",
      file_size: 612_352,
      firstSubmittedDaysAgo: 70,
      analysedDaysAgo: 12,
      reputation: malicious(82, "Backdoor implant (fictional QuietBeacon family)."),
      detections: detections(28, 7, 20, 13),
      findings: findings("malicious", "Backdoor.QuietBeacon", "Trojan.Generic"),
      tags: ["backdoor", "pedll"],
    },
  ],
  [
    4,
    {
      file_name: "setup_pack.exe",
      file_type: "Win32 EXE",
      file_size: 903_168,
      firstSubmittedDaysAgo: 6,
      analysedDaysAgo: 5,
      reputation: suspicious(55, "Packed executable; a few engines flag the packer."),
      detections: detections(1, 5, 40, 22),
      findings: findings("suspicious", "Packed.Generic", "Suspicious.Packer"),
      tags: ["packed", "peexe"],
    },
  ],
  [
    5,
    {
      malware_families: ["InkSteal"],
      file_name: "browser_sync.exe",
      file_type: "Win32 EXE",
      file_size: 1_104_896,
      firstSubmittedDaysAgo: 25,
      analysedDaysAgo: 4,
      reputation: malicious(87, "Credential stealer (fictional InkSteal family)."),
      detections: detections(36, 5, 18, 9),
      findings: findings("malicious", "PSW.InkSteal", "Stealer.Generic", "PSW.InkSteal"),
      tags: ["stealer", "peexe"],
    },
  ],
  [
    6,
    {
      malware_families: ["HollowShell"],
      file_name: "upload.aspx",
      file_type: "ASP.NET script",
      file_size: 4_608,
      firstSubmittedDaysAgo: 18,
      analysedDaysAgo: 3,
      reputation: malicious(80, "Web shell (fictional HollowShell family)."),
      detections: detections(19, 4, 30, 15),
      findings: findings("malicious", "WebShell.HollowShell", "Backdoor.ASP"),
      tags: ["webshell"],
    },
  ],
  [
    7,
    {
      file_name: "update.ps1",
      file_type: "PowerShell script",
      file_size: 8192,
      firstSubmittedDaysAgo: 11,
      analysedDaysAgo: 9,
      reputation: suspicious(50, "Script that downloads and runs another file."),
      detections: detections(2, 6, 44, 16),
      findings: findings("suspicious", "Downloader.Script", "Suspicious.PowerShell"),
      tags: ["script", "downloader"],
    },
  ],
  [
    8,
    {
      file_name: "inventory-agent.exe",
      file_type: "Win32 EXE",
      file_size: 5_242_880,
      firstSubmittedDaysAgo: 250,
      analysedDaysAgo: 20,
      reputation: benign(90, "The organisation's approved internal inventory tool."),
      detections: detections(0, 0, 70, 2),
      findings: [],
      tags: ["internal", "peexe"],
    },
  ],
];

// The EICAR standard antivirus test file: harmless by design, and detected by design. Only its
// published digests are kept here, never its content, which antivirus software would flag in this file.
const EICAR_HASHES: Record<HashType, string> = {
  md5: "44d88612fea8a8f36de82e1278abb02f",
  sha1: "3395856ce81f2b7382dee72602f798b642f14140",
  sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
};
const EICAR_SPEC: HashSpec = {
  file_name: "eicar.com",
  file_names: ["eicar.com", "eicar.com.txt"],
  file_type: "EICAR virus test files",
  file_size: 68,
  firstSubmittedDaysAgo: 4000,
  analysedDaysAgo: 1,
  reputation: {
    verdict: "unknown",
    confidence: null,
    summary:
      "The EICAR antivirus test file. Engines flag it on purpose so that people can test their protection; it contains no malicious code (sample record).",
  },
  detections: detections(62, 0, 0, 8),
  findings: findings("malicious", "EICAR-Test-File (not a virus)", "Eicar-Signature"),
  tags: ["test-file"],
};

type HashEntry = { spec: HashSpec; hashes: Record<HashType, string> };

const HASH_ENTRIES: HashEntry[] = [
  ...SAMPLE_SPECS.map(([n, spec]) => {
    const text = `arcradar-demo-sample-${n}`;
    return {
      spec,
      hashes: {
        md5: digest("md5", text),
        sha1: digest("sha1", text),
        sha256: digest("sha256", text),
      },
    };
  }),
  { spec: EICAR_SPEC, hashes: EICAR_HASHES },
];

const HASH_INDEX = new Map<string, HashEntry>(
  HASH_ENTRIES.flatMap((entry) =>
    Object.values(entry.hashes).map((hash) => [hash, entry] as const),
  ),
);

export function demoHashProfile(hash: string, type: HashType, now: Date): HashProfile | null {
  const entry = HASH_INDEX.get(hash);
  if (!entry) return null;
  const { spec } = entry;
  return {
    kind: "hash",
    hash,
    hash_type: type,
    hashes: entry.hashes,
    malware_families: spec.malware_families ?? [],
    file_name: spec.file_name ?? null,
    file_names: spec.file_names ?? (spec.file_name ? [spec.file_name] : []),
    file_type: spec.file_type ?? null,
    file_size: spec.file_size ?? null,
    first_submitted_at:
      spec.firstSubmittedDaysAgo === undefined ? null : daysAgo(now, spec.firstSubmittedDaysAgo),
    retrieved_at: now.toISOString(),
    reputation: spec.reputation,
    detections: spec.detections,
    findings: spec.findings,
    tags: spec.tags,
    last_analysed_at:
      spec.analysedDaysAgo === undefined ? null : daysAgo(now, spec.analysedDaysAgo),
  };
}

/** Subjects worth trying on each lookup page: the lookup pages offer them as one-click samples. */
export const DEMO_EXAMPLES: Record<"ip" | "domain" | "url" | "hash", string[]> = {
  ip: ["198.51.100.23", "8.8.8.8", "2001:db8:bad:1::5"],
  domain: ["harbor-lights-c2.example", "login-secure-update.example", "example.com"],
  url: [
    "https://login-secure-update.example/account/verify?session=demo",
    "http://198.51.100.23/gate.php",
  ],
  hash: [HASH_ENTRIES[0].hashes.sha256, HASH_ENTRIES[1].hashes.sha256, HASH_ENTRIES[5].hashes.md5],
};

/** Every subject the demo dataset knows, by kind. The tests use it to keep the dataset honest. */
export const DEMO_SUBJECTS = {
  ip: Object.keys(IP_SPECS),
  domain: Object.keys(DOMAIN_SPECS),
  url: Object.keys(URL_SPECS),
  hash: [...HASH_INDEX.keys()],
};
