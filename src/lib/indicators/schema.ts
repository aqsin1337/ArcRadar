import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import {
  DATA_ORIGINS,
  INDICATOR_SORT_FIELDS,
  INDICATOR_STATUSES,
  INDICATOR_TYPES,
  MAX_INDICATOR_TAGS,
  MAX_TAG_LENGTH,
  SEVERITIES,
  VERDICTS,
} from "./constants";
import { canonicalizeIndicatorValue, validateIndicatorValue } from "./value";

export const indicatorTypeSchema = z.enum(INDICATOR_TYPES);
export const indicatorStatusSchema = z.enum(INDICATOR_STATUSES);
export const severitySchema = z.enum(SEVERITIES);
export const verdictSchema = z.enum(VERDICTS);
export const originSchema = z.enum(DATA_ORIGINS);

const isoDateTime = z.iso.datetime({ offset: true, error: "Enter a valid date and time." });

const TAG_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} _.:+#/-]*$/u;

export const tagNameSchema = z
  .string()
  .trim()
  .min(1, "A tag cannot be empty.")
  .max(MAX_TAG_LENGTH, `A tag can have at most ${MAX_TAG_LENGTH} characters.`)
  .regex(TAG_PATTERN, "Tags may contain letters, numbers, spaces and - _ . : + # /");

/** A list of tag names; duplicates (ignoring case) are dropped, keeping the first spelling. */
export const tagsSchema = z
  .array(tagNameSchema)
  .max(MAX_INDICATOR_TAGS, `An indicator can have at most ${MAX_INDICATOR_TAGS} tags.`)
  .transform((tags) => {
    const seen = new Set<string>();
    return tags.filter((tag) => {
      const key = tag.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  });

// An empty description means "no description".
const descriptionSchema = z
  .string()
  .trim()
  .max(5000, "The description can have at most 5000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const sourceSchema = z
  .string()
  .trim()
  .min(1, "Enter a source, for example manual.")
  .max(100, "The source can have at most 100 characters.");

const confidenceSchema = z
  .number({ error: "Enter a number from 0 to 100." })
  .int("Enter a whole number from 0 to 100.")
  .min(0, "Confidence cannot be below 0.")
  .max(100, "Confidence cannot be above 100.");

function checkSeenOrder(
  input: { first_seen?: string; last_seen?: string },
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

/** Body of POST /api/indicators. `origin` is deliberately absent: created records are always local. */
export const createIndicatorSchema = z
  .strictObject({
    type: indicatorTypeSchema,
    value: z.string().trim().min(1, "Enter a value.").max(2048, "The value is too long."),
    severity: severitySchema.optional(),
    verdict: verdictSchema.optional(),
    status: indicatorStatusSchema.optional(),
    confidence: confidenceSchema.optional(),
    source: sourceSchema.optional(),
    description: descriptionSchema.optional(),
    first_seen: isoDateTime.optional(),
    last_seen: isoDateTime.optional(),
    tags: tagsSchema.optional(),
  })
  .superRefine((input, context) => {
    const problem = validateIndicatorValue(input.type, input.value);
    if (problem) context.addIssue({ code: "custom", path: ["value"], message: problem });
    checkSeenOrder(input, context);
  })
  .transform((input) => ({ ...input, value: canonicalizeIndicatorValue(input.type, input.value) }));

/**
 * Body of PATCH /api/indicators/:id. The type and value identify the indicator and cannot change
 * (delete and re-create to fix a typo); origin and ownership are never editable.
 */
export const updateIndicatorSchema = z
  .strictObject({
    severity: severitySchema.optional(),
    verdict: verdictSchema.optional(),
    status: indicatorStatusSchema.optional(),
    confidence: confidenceSchema.optional(),
    source: sourceSchema.optional(),
    description: descriptionSchema.optional(),
    first_seen: isoDateTime.optional(),
    last_seen: isoDateTime.optional(),
    tags: tagsSchema.optional(),
  })
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide at least one field to update.",
  })
  .superRefine(checkSeenOrder);

export const indicatorIdSchema = z.uuid({ error: "The indicator id is not valid." });

// Form fields arrive as "" when left empty; treat that as "not set".
const blankToUndefined = <T extends z.ZodType>(schema: T) =>
  z.preprocess((value) => (value === "" ? undefined : value), schema.optional());

/** Query string of GET /api/indicators and of the /indicators page. */
export const indicatorListQuerySchema = paginationQuerySchema.extend({
  q: blankToUndefined(z.string().trim().max(200, "The search text is too long.")),
  type: blankToUndefined(indicatorTypeSchema),
  status: blankToUndefined(indicatorStatusSchema),
  verdict: blankToUndefined(verdictSchema),
  severity: blankToUndefined(severitySchema),
  origin: blankToUndefined(originSchema),
  tag: blankToUndefined(z.string().trim().min(1).max(MAX_TAG_LENGTH)),
  sort: z.enum(INDICATOR_SORT_FIELDS).default("last_seen"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type CreateIndicatorInput = z.output<typeof createIndicatorSchema>;
export type UpdateIndicatorInput = z.output<typeof updateIndicatorSchema>;
export type IndicatorListQuery = z.output<typeof indicatorListQuerySchema>;

type RawParams = Record<string, string | string[] | undefined>;

/**
 * For the list page, where a hand-edited URL must never crash the page: invalid parameters fall back
 * to the defaults and the caller is told, so it can say so.
 */
export function parseIndicatorListParams(params: RawParams): {
  query: IndicatorListQuery;
  ignoredInvalid: boolean;
} {
  const flat = Object.fromEntries(
    Object.entries(params).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value]),
  );
  const parsed = indicatorListQuerySchema.safeParse(flat);
  if (parsed.success) return { query: parsed.data, ignoredInvalid: false };
  return { query: indicatorListQuerySchema.parse({}), ignoredInvalid: true };
}
