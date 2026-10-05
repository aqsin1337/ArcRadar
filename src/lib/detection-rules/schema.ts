import { z } from "zod";
import { SEVERITIES } from "@/lib/indicators/constants";
import {
  DETECTION_RULE_FIELD_OPS,
  DETECTION_RULE_FIELDS,
  DETECTION_RULE_ID_MAX,
  DETECTION_RULE_ID_MIN,
  DETECTION_RULE_OPS,
} from "./constants";

const name = z
  .string()
  .trim()
  .min(1, "Enter a name.")
  .max(200, "The name can have at most 200 characters.");

const description = z
  .string()
  .trim()
  .max(2000, "The description can have at most 2000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const ruleId = z
  .number()
  .int({ error: "The rule id must be a whole number." })
  .min(
    DETECTION_RULE_ID_MIN,
    `The rule id must be between ${DETECTION_RULE_ID_MIN} and ${DETECTION_RULE_ID_MAX}.`,
  )
  .max(
    DETECTION_RULE_ID_MAX,
    `The rule id must be between ${DETECTION_RULE_ID_MIN} and ${DETECTION_RULE_ID_MAX}.`,
  );

/** One row of the condition builder. `detection_rule_matches()` is the actual authority. */
const condition = z
  .strictObject({
    field: z.enum(DETECTION_RULE_FIELDS),
    op: z.enum(DETECTION_RULE_OPS),
    value: z
      .string()
      .trim()
      .min(1, "Enter a value.")
      .max(200, "The value can have at most 200 characters."),
  })
  .refine(
    (input) => (DETECTION_RULE_FIELD_OPS[input.field] as readonly string[]).includes(input.op),
    {
      message: "That comparison is not available for this field.",
      path: ["op"],
    },
  );

const conditions = z
  .array(condition)
  .min(1, "Add at least one condition.")
  .max(10, "A rule can have at most 10 conditions.");

/** Body of POST /api/detection-rules. Origin is not the client's to set: it is always local. */
export const createDetectionRuleSchema = z.strictObject({
  id: ruleId,
  name,
  description: description.optional(),
  conditions,
  severity: z.enum(SEVERITIES).optional(),
  priority: z.number().int().min(1).max(1000).optional(),
  enabled: z.boolean().optional(),
});

/** Body of PATCH /api/detection-rules/:id. The id itself is fixed once created. */
export const updateDetectionRuleSchema = z
  .strictObject({
    name: name.optional(),
    description: description.optional(),
    conditions: conditions.optional(),
    severity: z.enum(SEVERITIES).nullable().optional(),
    priority: z.number().int().min(1).max(1000).optional(),
    enabled: z.boolean().optional(),
  })
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide at least one field to update.",
  });

export type CreateDetectionRuleInput = z.output<typeof createDetectionRuleSchema>;
export type UpdateDetectionRuleInput = z.output<typeof updateDetectionRuleSchema>;
