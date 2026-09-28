import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { DATA_ORIGINS } from "@/lib/indicators/constants";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import {
  ACTOR_SORT_FIELDS,
  CAMPAIGN_SORT_FIELDS,
  CAMPAIGN_STATUSES,
  MALWARE_SORT_FIELDS,
  TECHNIQUE_ID,
  TECHNIQUE_SORT_FIELDS,
} from "./constants";

const order = z.enum(["asc", "desc"]);
const search = blankToUndefined(z.string().trim().max(200, "The search text is too long."));
const origin = blankToUndefined(z.enum(DATA_ORIGINS));

export const actorListQuerySchema = paginationQuerySchema.extend({
  q: search,
  origin,
  sort: z.enum(ACTOR_SORT_FIELDS).default("name"),
  order: order.default("asc"),
});

export const campaignListQuerySchema = paginationQuerySchema.extend({
  q: search,
  status: blankToUndefined(z.enum(CAMPAIGN_STATUSES)),
  origin,
  sort: z.enum(CAMPAIGN_SORT_FIELDS).default("last_seen"),
  order: order.default("desc"),
});

export const malwareListQuerySchema = paginationQuerySchema.extend({
  q: search,
  type: blankToUndefined(z.string().trim().min(1).max(100)),
  origin,
  sort: z.enum(MALWARE_SORT_FIELDS).default("name"),
  order: order.default("asc"),
});

export const techniqueListQuerySchema = paginationQuerySchema.extend({
  q: search,
  tactic: blankToUndefined(z.string().trim().min(1).max(100)),
  sort: z.enum(TECHNIQUE_SORT_FIELDS).default("id"),
  order: order.default("asc"),
});

export type ActorListQuery = z.output<typeof actorListQuerySchema>;
export type CampaignListQuery = z.output<typeof campaignListQuerySchema>;
export type MalwareListQuery = z.output<typeof malwareListQuerySchema>;
export type TechniqueListQuery = z.output<typeof techniqueListQuerySchema>;

/** The list pages' queries from their `searchParams`; a hand-edited URL falls back to the defaults. */
export const parseActorListParams = (params: RawParams) =>
  parseListParams(actorListQuerySchema, params);
export const parseCampaignListParams = (params: RawParams) =>
  parseListParams(campaignListQuerySchema, params);
export const parseMalwareListParams = (params: RawParams) =>
  parseListParams(malwareListQuerySchema, params);
export const parseTechniqueListParams = (params: RawParams) =>
  parseListParams(techniqueListQuerySchema, params);

// --- Bodies ---------------------------------------------------------------------------------------

const isoDateTime = z.iso.datetime({ offset: true, error: "Enter a valid date and time." });

const name = z
  .string()
  .trim()
  .min(1, "Enter a name.")
  .max(200, "The name can have at most 200 characters.");

// An empty text means "not set".
const optionalText = (max: number, label: string) =>
  z
    .string()
    .trim()
    .max(max, `The ${label} can have at most ${max} characters.`)
    .transform((text) => (text === "" ? null : text))
    .nullable();

const description = optionalText(10000, "description");

/** A list of short labels; blanks and duplicates (ignoring case) are dropped, the first spelling stays. */
const labels = (noun: string, max = 30) =>
  z
    .array(z.string().trim().max(100, `A ${noun} can have at most 100 characters.`))
    .max(max, `At most ${max} ${noun}s.`)
    .transform((values) => {
      const seen = new Set<string>();
      return values.filter((value) => {
        const key = value.toLowerCase();
        if (value === "" || seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    });

const ids = (noun: string) =>
  z
    .array(z.uuid({ error: `A ${noun} id is not valid.` }))
    .max(200, `At most 200 ${noun}s can be linked.`)
    .transform((values) => [...new Set(values)]);

const techniqueIds = z
  .array(z.string().regex(TECHNIQUE_ID, "A technique id looks like T1566 or T1078.001."))
  .max(200, "At most 200 techniques can be linked.")
  .transform((values) => [...new Set(values)]);

function checkSeenOrder(
  input: { first_seen?: string | null; last_seen?: string | null },
  context: z.RefinementCtx,
) {
  if (
    input.first_seen &&
    input.last_seen &&
    Date.parse(input.last_seen) < Date.parse(input.first_seen)
  ) {
    context.addIssue({
      code: "custom",
      path: ["last_seen"],
      message: "Last seen cannot be earlier than first seen.",
    });
  }
}

const atLeastOne = { message: "Provide at least one field to update." };

// Bodies are strict and never carry `origin`, ownership or ids: created records are always local and
// attributed to the caller by the database. Link lists replace the whole set when present and leave it
// alone when absent.

const actorFields = {
  name,
  aliases: labels("alias"),
  description,
  motivation: optionalText(200, "motivation"),
  attribution_country: optionalText(100, "country"),
  target_industries: labels("industry"),
  target_countries: labels("country"),
  first_seen: isoDateTime.nullable(),
  last_seen: isoDateTime.nullable(),
  malware_ids: ids("malware"),
  campaign_ids: ids("campaign"),
  technique_ids: techniqueIds,
};

export const createActorSchema = z
  .strictObject(actorFields)
  .partial({
    aliases: true,
    description: true,
    motivation: true,
    attribution_country: true,
    target_industries: true,
    target_countries: true,
    first_seen: true,
    last_seen: true,
    malware_ids: true,
    campaign_ids: true,
    technique_ids: true,
  })
  .superRefine(checkSeenOrder);

export const updateActorSchema = z
  .strictObject(actorFields)
  .partial()
  .refine((input) => Object.keys(input).length > 0, atLeastOne)
  .superRefine(checkSeenOrder);

const campaignFields = {
  name,
  description,
  status: z.enum(CAMPAIGN_STATUSES),
  first_seen: isoDateTime.nullable(),
  last_seen: isoDateTime.nullable(),
  actor_ids: ids("threat actor"),
};

export const createCampaignSchema = z
  .strictObject(campaignFields)
  .partial({
    description: true,
    status: true,
    first_seen: true,
    last_seen: true,
    actor_ids: true,
  })
  .superRefine(checkSeenOrder);

export const updateCampaignSchema = z
  .strictObject(campaignFields)
  .partial()
  .refine((input) => Object.keys(input).length > 0, atLeastOne)
  .superRefine(checkSeenOrder);

const malwareFields = {
  name,
  malware_type: optionalText(100, "type"),
  platforms: labels("platform", 20),
  description,
  actor_ids: ids("threat actor"),
};

export const createMalwareSchema = z.strictObject(malwareFields).partial({
  malware_type: true,
  platforms: true,
  description: true,
  actor_ids: true,
});

export const updateMalwareSchema = z
  .strictObject(malwareFields)
  .partial()
  .refine((input) => Object.keys(input).length > 0, atLeastOne);

export type CreateActorInput = z.output<typeof createActorSchema>;
export type UpdateActorInput = z.output<typeof updateActorSchema>;
export type CreateCampaignInput = z.output<typeof createCampaignSchema>;
export type UpdateCampaignInput = z.output<typeof updateCampaignSchema>;
export type CreateMalwareInput = z.output<typeof createMalwareSchema>;
export type UpdateMalwareInput = z.output<typeof updateMalwareSchema>;

export const entityIdSchema = z.uuid({ error: "The id is not valid." });
export const techniqueIdSchema = z
  .string()
  .trim()
  .transform((id) => id.toUpperCase())
  .pipe(z.string().regex(TECHNIQUE_ID, "A technique id looks like T1566 or T1078.001."));
