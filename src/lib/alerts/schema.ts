import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { DATA_ORIGINS, SEVERITIES } from "@/lib/indicators/constants";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import { ALERT_SORT_FIELDS, ALERT_STATUSES, ASSIGNEE_ME, ASSIGNEE_NONE } from "./constants";

const assigneeFilter = z.union([z.literal(ASSIGNEE_ME), z.literal(ASSIGNEE_NONE), z.uuid()]);

/** Query string of GET /api/alerts and of the /alerts page. */
export const alertListQuerySchema = paginationQuerySchema.extend({
  q: blankToUndefined(z.string().trim().max(200, "The search text is too long.")),
  status: blankToUndefined(z.enum(ALERT_STATUSES)),
  severity: blankToUndefined(z.enum(SEVERITIES)),
  origin: blankToUndefined(z.enum(DATA_ORIGINS)),
  source: blankToUndefined(z.string().trim().min(1).max(100)),
  assignee: blankToUndefined(assigneeFilter),
  // Unset (the default) hides a duplicate alert from the queue; "show" reveals it alongside its primary.
  duplicates: blankToUndefined(z.literal("show")),
  sort: z.enum(ALERT_SORT_FIELDS).default("created_at"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type AlertListQuery = z.output<typeof alertListQuerySchema>;

/** The list page's query from its `searchParams`; a hand-edited URL falls back to the defaults. */
export function parseAlertListParams(params: RawParams) {
  return parseListParams(alertListQuerySchema, params);
}

const description = z
  .string()
  .trim()
  .max(5000, "The description can have at most 5000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

/** Body of POST /api/alerts. Alerts created here are manual and local: origin, source and owner are not the client's to set. */
export const createAlertSchema = z.strictObject({
  title: z
    .string()
    .trim()
    .min(1, "Enter a title.")
    .max(300, "The title can have at most 300 characters."),
  description: description.optional(),
  severity: z.enum(SEVERITIES).optional(),
  indicator_id: z.uuid({ error: "The indicator id is not valid." }).optional(),
});

/** Body of PATCH /api/alerts/:id: the workflow (status) and the assignee. `assigned_to` may be "me". */
export const updateAlertSchema = z
  .strictObject({
    status: z.enum(ALERT_STATUSES).optional(),
    assigned_to: z
      .union([z.uuid({ error: "The user id is not valid." }), z.literal(ASSIGNEE_ME), z.null()])
      .optional(),
  })
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide a status or an assignee to update.",
  });

export const alertIdSchema = z.uuid({ error: "The alert id is not valid." });

export type CreateAlertInput = z.output<typeof createAlertSchema>;
export type UpdateAlertInput = z.output<typeof updateAlertSchema>;
