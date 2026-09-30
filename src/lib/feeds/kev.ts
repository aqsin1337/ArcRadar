import { z } from "zod";

/*
 * CISA's Known Exploited Vulnerabilities catalog (public domain): CVEs that are being exploited in
 * the wild right now. Each becomes a vulnerability record with exploit status "exploited_in_wild".
 * The catalog carries no CVSS score, so the severity is a judgement about the fact itself: a CVE
 * that is exploited in the wild is "high", and "critical" when it is known to be used in
 * ransomware campaigns. `published_at` is the date CISA added it to the catalog, which is the
 * date that matters for "when did this become urgent".
 */

const entry = z.object({
  cveID: z.string(),
  vendorProject: z.string().nullish(),
  product: z.string().nullish(),
  vulnerabilityName: z.string().nullish(),
  dateAdded: z.string().nullish(),
  shortDescription: z.string().nullish(),
  requiredAction: z.string().nullish(),
  knownRansomwareCampaignUse: z.string().nullish(),
  notes: z.string().nullish(),
});

const catalog = z.object({ vulnerabilities: z.array(z.unknown()) });

export type KevVulnerability = {
  cve_id: string;
  title: string;
  description: string;
  severity: "high" | "critical";
  exploit_status: "exploited_in_wild";
  remediation: string | null;
  reference_urls: string[];
  published_at: string | null;
  affected_products: { vendor: string; product: string }[];
};

const MAX_REFERENCES = 6;

function referencesFrom(cve: string, notes: string | null | undefined): string[] {
  const urls = [`https://nvd.nist.gov/vuln/detail/${cve}`];
  for (const match of (notes ?? "").matchAll(/https?:\/\/[^\s;,]+/g)) {
    const url = match[0].replace(/[).]+$/, "");
    if (!urls.includes(url)) urls.push(url);
    if (urls.length >= MAX_REFERENCES) break;
  }
  return urls;
}

function dateAdded(value: string | null | undefined): string | null {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** The catalog as vulnerability records, newest first; entries that do not parse are dropped. */
export function parseKevCatalog(body: unknown): KevVulnerability[] {
  const parsed = catalog.safeParse(body);
  if (!parsed.success) return [];

  const records: KevVulnerability[] = [];
  const seen = new Set<string>();
  for (const raw of parsed.data.vulnerabilities) {
    const item = entry.safeParse(raw);
    if (!item.success) continue;
    const e = item.data;
    const cve = e.cveID.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cve) || seen.has(cve)) continue;
    seen.add(cve);

    const vendor = e.vendorProject?.trim() ?? "";
    const product = e.product?.trim() ?? "";
    records.push({
      cve_id: cve,
      title: (e.vulnerabilityName?.trim() || cve).slice(0, 300),
      description: e.shortDescription?.trim() ?? "",
      severity: e.knownRansomwareCampaignUse === "Known" ? "critical" : "high",
      exploit_status: "exploited_in_wild",
      remediation: e.requiredAction?.trim() || null,
      reference_urls: referencesFrom(cve, e.notes),
      published_at: dateAdded(e.dateAdded),
      affected_products: vendor && product ? [{ vendor, product }] : [],
    });
  }
  return records.sort((a, b) => (b.published_at ?? "").localeCompare(a.published_at ?? ""));
}
