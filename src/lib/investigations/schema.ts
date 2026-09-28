import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { ASSIGNEE_ME, ASSIGNEE_NONE } from "@/lib/alerts/constants";
import { DATA_ORIGINS, MAX_TAG_LENGTH } from "@/lib/indicators/constants";
import { tagsSchema } from "@/lib/indicators/schema";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import {
  INVESTIGATION_SORT_FIELDS,
  INVESTIGATION_STATUSES,
  MAX_LINKED_ALERTS,
  MAX_LINKED_INDICATORS,
  PRIORITIES,
} from "./constants";

const analystFilter = z.union([z.literal(ASSIGNEE_ME), z.literal(ASSIGNEE_NONE), z.uuid()]);

/** Query string of GET /api/investigations and of the /investigations page. */
export const investigationListQuerySchema = paginationQuerySchema.extend({
  q: blankToUndefined(z.string().trim().max(200, "The search text is too long.")),
  status: blankToUndefined(z.enum(INVESTIGATION_STATUSES)),
  priority: blankToUndefined(z.enum(PRIORITIES)),
  origin: blankToUndefined(z.enum(DATA_ORIGINS)),
  tag: blankToUndefined(z.string().trim().min(1).max(MAX_TAG_LENGTH)),
  analyst: blankToUndefined(analystFilter),
  sort: z.enum(INVESTIGATION_SORT_FIELDS).default("updated_at"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type InvestigationListQuery = z.output<typeof investigationListQuerySchema>;

/** The list page's query from its `searchParams`; a hand-edited URL falls back to the defaults. */
export function parseInvestigationListParams(params: RawParams) {
  return parseListParams(investigationListQuerySchema, params);
}

const uuid = (what: string) => z.uuid({ error: `The ${what} id is not valid.` });

// An empty description means "no description".
const description = z
  .string()
  .trim()
  .max(10_000, "The description can have at most 10000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const title = z
  .string()
  .trim()
  .min(1, "Enter a title.")
  .max(300, "The title can have at most 300 characters.");

const analyst = z.union([uuid("analyst"), z.literal(ASSIGNEE_ME), z.null()]);

const uniqueIds = (what: string, max: number) =>
  z
    .array(uuid(what))
    .max(max, `At most ${max} ${what}s can be linked at once.`)
    .transform((ids) => [...new Set(ids)]);

/**
 * Body of POST /api/investigations. `analyst_id` defaults to the caller; `null` leaves it unassigned.
 * Origin, ownership and the status (a new investigation is always open) are not the client's to set.
 */
export const createInvestigationSchema = z.strictObject({
  title,
  description: description.optional(),
  priority: z.enum(PRIORITIES).optional(),
  analyst_id: analyst.optional(),
  tags: tagsSchema.optional(),
  indicator_ids: uniqueIds("indicator", MAX_LINKED_INDICATORS).optional(),
  alert_ids: uniqueIds("alert", MAX_LINKED_ALERTS).optional(),
});

/** Body of PATCH /api/investigations/:id. */
export const updateInvestigationSchema = z
  .strictObject({
    title: title.optional(),
    description: description.optional(),
    status: z.enum(INVESTIGATION_STATUSES).optional(),
    priority: z.enum(PRIORITIES).optional(),
    analyst_id: analyst.optional(),
    tags: tagsSchema.optional(),
  })
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide at least one field to update.",
  });

export const addIndicatorLinkSchema = z.strictObject({ indicator_id: uuid("indicator") });
export const addAlertLinkSchema = z.strictObject({ alert_id: uuid("alert") });

export const noteSchema = z.strictObject({
  body: z
    .string()
    .trim()
    .min(1, "Write something.")
    .max(10_000, "A note can have at most 10000 characters."),
});

export const evidenceSchema = z.strictObject({
  title: z
    .string()
    .trim()
    .min(1, "Enter a title.")
    .max(200, "The title can have at most 200 characters."),
  location: z
    .string()
    .trim()
    .min(1, "Say where the evidence is (a link, a file hash, a ticket number, ...).")
    .max(2048, "The location is too long."),
  description: z
    .string()
    .trim()
    .max(5000, "The description can have at most 5000 characters.")
    .transform((text) => (text === "" ? null : text))
    .nullable()
    .optional(),
});

export const createChecklistItemSchema = z.strictObject({
  text: z
    .string()
    .trim()
    .min(1, "Write a checklist item.")
    .max(500, "A checklist item can have at most 500 characters."),
});

export const updateChecklistItemSchema = z.strictObject({ done: z.boolean() });

export const investigationIdSchema = uuid("investigation");
export const subIdSchema = uuid("record");

export type CreateInvestigationInput = z.output<typeof createInvestigationSchema>;
export type UpdateInvestigationInput = z.output<typeof updateInvestigationSchema>;
export type NoteInput = z.output<typeof noteSchema>;
export type EvidenceInput = z.output<typeof evidenceSchema>;
export type CreateChecklistItemInput = z.output<typeof createChecklistItemSchema>;
export type UpdateChecklistItemInput = z.output<typeof updateChecklistItemSchema>;
