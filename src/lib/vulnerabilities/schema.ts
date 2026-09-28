import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { DATA_ORIGINS, SEVERITIES } from "@/lib/indicators/constants";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import { EXPLOIT_STATUSES, VULNERABILITY_SORT_FIELDS } from "./constants";

const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/i;

/** A CVE id from a URL or a body, in its canonical upper-case form. */
export const cveIdSchema = z
  .string()
  .trim()
  .regex(CVE_ID, "Enter a CVE id such as CVE-2021-44228.")
  .transform((id) => id.toUpperCase());

export const isCveId = (value: string) => CVE_ID.test(value);

/** Body of POST /api/vulnerabilities/import. Only the id: everything else comes from the provider. */
export const importVulnerabilitySchema = z.strictObject({ cve_id: cveIdSchema });

/** Query string of GET /api/vulnerabilities and of the /vulnerabilities page. */
export const vulnerabilityListQuerySchema = paginationQuerySchema.extend({
  q: blankToUndefined(z.string().trim().max(200, "The search text is too long.")),
  severity: blankToUndefined(z.enum(SEVERITIES)),
  exploit_status: blankToUndefined(z.enum(EXPLOIT_STATUSES)),
  origin: blankToUndefined(z.enum(DATA_ORIGINS)),
  min_cvss: blankToUndefined(z.coerce.number().min(0).max(10)),
  sort: z.enum(VULNERABILITY_SORT_FIELDS).default("published_at"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type VulnerabilityListQuery = z.output<typeof vulnerabilityListQuerySchema>;

/** The list page's query from its `searchParams`; a hand-edited URL falls back to the defaults. */
export function parseVulnerabilityListParams(params: RawParams) {
  return parseListParams(vulnerabilityListQuerySchema, params);
}
