import { z } from "zod";
import { RESPONSE_ACTION_STATUSES } from "./constants";

const title = z
  .string()
  .trim()
  .min(1, "Enter a title.")
  .max(200, "The title can have at most 200 characters.");

// An empty description/category/notes means "none".
const description = z
  .string()
  .trim()
  .max(2000, "The description can have at most 2000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const category = z
  .string()
  .trim()
  .max(50, "The category can have at most 50 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const notes = z
  .string()
  .trim()
  .max(2000, "Notes can have at most 2000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

/** Body of POST /api/response-actions. Origin is not the client's to set: it is always local. */
export const createResponseActionSchema = z.strictObject({
  title,
  description: description.optional(),
  category: category.optional(),
});

/** Body of PATCH /api/response-actions/:id. */
export const updateResponseActionSchema = z
  .strictObject({
    title: title.optional(),
    description: description.optional(),
    category: category.optional(),
  })
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide at least one field to update.",
  });

export const responseActionIdSchema = z.uuid({ error: "The action id is not valid." });
export const responseActionLogIdSchema = z.uuid({ error: "The log entry id is not valid." });

/** Body of POST /api/alerts/:id/response-actions: attach an existing catalog action. */
export const attachResponseActionSchema = z.strictObject({
  action_id: z.uuid({ error: "The action id is not valid." }),
});

/** Body of PATCH /api/alerts/:id/response-actions/:logId. */
export const updateResponseActionLogSchema = z.strictObject({
  status: z.enum(RESPONSE_ACTION_STATUSES),
  notes: notes.optional(),
});

export type CreateResponseActionInput = z.output<typeof createResponseActionSchema>;
export type UpdateResponseActionInput = z.output<typeof updateResponseActionSchema>;
export type AttachResponseActionInput = z.output<typeof attachResponseActionSchema>;
export type UpdateResponseActionLogInput = z.output<typeof updateResponseActionLogSchema>;
