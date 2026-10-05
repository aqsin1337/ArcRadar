import { z } from "zod";
import {
  FREQUENCY_MAX,
  FREQUENCY_MIN,
  MAX_SAME_FIELDS,
  TIMEFRAME_MAX,
  TIMEFRAME_MIN,
  MAX_CONDITION_VALUE,
  MAX_CONDITIONS,
  MITRE_ID_PATTERN,
  WAZUH_CONDITION_OPS,
  WAZUH_FIELD_PATTERN,
  WAZUH_GROUP_PATTERN,
  WAZUH_PARENT_KINDS,
  WAZUH_RULE_ID_MAX,
  WAZUH_RULE_ID_MIN,
  WAZUH_SID_PATTERN,
} from "./constants";

/**
 * A pattern is only ever run by Wazuh (PCRE2) on the Manager, but a slow one there hurts every event
 * that passes through it. This rejects the constructs that make matching unpredictable: anything
 * `(?...)` other than a plain non-capturing group, back-references, a quantified group that itself
 * contains a quantifier (the classic catastrophic-backtracking shape), and a pattern the regex engine
 * here cannot even compile. It is a guard, not a proof; a rule is still reviewed before it is pushed.
 */
export function checkRegex(pattern: string): string | null {
  if (/\(\?(?!:)/.test(pattern))
    return "Only plain groups are allowed; lookarounds and flags are not.";
  if (/\\[1-9kg]/.test(pattern)) return "Back-references are not allowed.";
  if (/\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)[+*{]/.test(pattern)) {
    return "A repeated group that itself repeats can make matching very slow.";
  }
  if (/[+*}][+*]/.test(pattern.replace(/\\./g, ""))) return "Stacked repetition is not allowed.";
  try {
    new RegExp(pattern);
  } catch {
    return "The pattern is not a valid regular expression.";
  }
  return null;
}

const name = z
  .string()
  .trim()
  .min(1, "Enter a name.")
  .max(200, "The name can have at most 200 characters.")
  .refine((text) => !/[\u0000-\u001f]/.test(text), "The name cannot contain control characters.");

const description = z
  .string()
  .trim()
  .max(2000, "The description can have at most 2000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const condition = z
  .strictObject({
    field: z
      .string()
      .trim()
      .regex(
        WAZUH_FIELD_PATTERN,
        "Use a Wazuh field such as win.eventdata.commandLine (win., data., syscheck. or agent.).",
      ),
    op: z.enum(WAZUH_CONDITION_OPS),
    value: z
      .string()
      .min(1, "Enter a value.")
      .max(MAX_CONDITION_VALUE, `The value can have at most ${MAX_CONDITION_VALUE} characters.`)
      .refine(
        (text) => !/[\u0000-\u001f]/.test(text),
        "The value cannot contain control characters.",
      ),
  })
  .superRefine((input, ctx) => {
    if (input.op !== "regex") return;
    const problem = checkRegex(input.value);
    if (problem) ctx.addIssue({ code: "custom", path: ["value"], message: problem });
  });

const conditions = z
  .array(condition)
  .max(MAX_CONDITIONS, `A rule can have at most ${MAX_CONDITIONS} conditions.`);

const mitreIds = z
  .array(
    z
      .string()
      .trim()
      .toUpperCase()
      .regex(MITRE_ID_PATTERN, "Use a technique id such as T1562.001."),
  )
  .max(10, "At most 10 techniques.")
  .transform((ids) => [...new Set(ids)]);

const level = z
  .number()
  .int({ error: "The level must be a whole number." })
  .min(1, "The level is 1 to 15.")
  .max(15, "The level is 1 to 15.");

const ruleId = z
  .number()
  .int({ error: "The rule id must be a whole number." })
  .min(
    WAZUH_RULE_ID_MIN,
    `The rule id must be between ${WAZUH_RULE_ID_MIN} and ${WAZUH_RULE_ID_MAX}.`,
  )
  .max(
    WAZUH_RULE_ID_MAX,
    `The rule id must be between ${WAZUH_RULE_ID_MIN} and ${WAZUH_RULE_ID_MAX}.`,
  );

const parentFields = {
  parent_kind: z.enum(WAZUH_PARENT_KINDS),
  parent_value: z.string().trim().min(1, "Enter a group or rule id."),
};

function checkParent(input: { parent_kind?: string; parent_value?: string }, ctx: z.RefinementCtx) {
  if (input.parent_kind === undefined || input.parent_value === undefined) return;
  const pattern = input.parent_kind === "sid" ? WAZUH_SID_PATTERN : WAZUH_GROUP_PATTERN;
  if (!pattern.test(input.parent_value)) {
    ctx.addIssue({
      code: "custom",
      path: ["parent_value"],
      message:
        input.parent_kind === "sid"
          ? "A parent rule id is a number."
          : "Use letters, digits, _ . - only.",
    });
  }
}

const frequency = z
  .number()
  .int({ error: "Enter a whole number of times." })
  .min(FREQUENCY_MIN, `The count is ${FREQUENCY_MIN} to ${FREQUENCY_MAX}.`)
  .max(FREQUENCY_MAX, `The count is ${FREQUENCY_MIN} to ${FREQUENCY_MAX}.`);

const timeframe = z
  .number()
  .int({ error: "Enter a whole number of seconds." })
  .min(TIMEFRAME_MIN, `The window is ${TIMEFRAME_MIN} to ${TIMEFRAME_MAX} seconds.`)
  .max(TIMEFRAME_MAX, `The window is ${TIMEFRAME_MIN} to ${TIMEFRAME_MAX} seconds.`);

const sameFields = z
  .array(
    z
      .string()
      .trim()
      .regex(WAZUH_FIELD_PATTERN, "Use a Wazuh field such as win.eventdata.ipAddress."),
  )
  .max(MAX_SAME_FIELDS, `At most ${MAX_SAME_FIELDS} fields.`)
  .transform((fields) => [...new Set(fields)]);

/** Repetition is all-or-nothing, and an ordinary rule still needs a condition of its own. */
function checkRepetition(
  input: {
    frequency?: number | null;
    timeframe?: number | null;
    same_fields?: string[];
    conditions?: unknown[];
  },
  ctx: z.RefinementCtx,
  { creating }: { creating: boolean },
) {
  const repeats = input.frequency !== undefined && input.frequency !== null;
  if (repeats !== (input.timeframe !== undefined && input.timeframe !== null)) {
    ctx.addIssue({
      code: "custom",
      path: [repeats ? "timeframe" : "frequency"],
      message: "Set both the count and the time window, or neither.",
    });
  }
  if (!repeats && (input.same_fields?.length ?? 0) > 0) {
    ctx.addIssue({
      code: "custom",
      path: ["same_fields"],
      message: '"Same value in" only applies to a rule that counts repeats.',
    });
  }
  if (creating && !repeats && (input.conditions?.length ?? 0) === 0) {
    ctx.addIssue({
      code: "custom",
      path: ["conditions"],
      message: "Add at least one condition, or make this a repeating rule.",
    });
  }
}

/** The part of a rule an AI answer or a person supplies. No id, status, source or origin here. */
const definitionShape = {
  name,
  description: description.optional(),
  level,
  ...parentFields,
  conditions,
  mitre_ids: mitreIds.default([]),
  frequency: frequency.nullable().default(null),
  timeframe: timeframe.nullable().default(null),
  same_fields: sameFields.default([]),
};

/** Body of POST /api/wazuh-rules. `id` is optional: the server picks the next free one. */
export const createWazuhRuleSchema = z
  .strictObject({ id: ruleId.optional(), ...definitionShape })
  .superRefine(checkParent)
  .superRefine((input, ctx) => checkRepetition(input, ctx, { creating: true }));

/** What the AI must return (same rules, so an answer that breaks one is refused, never stored). */
export const aiWazuhRuleSchema = z
  .object(definitionShape)
  .superRefine(checkParent)
  .superRefine((input, ctx) => checkRepetition(input, ctx, { creating: true }));

/** Body of PATCH /api/wazuh-rules/:id. */
export const updateWazuhRuleSchema = z
  .strictObject({
    name: name.optional(),
    description: description.optional(),
    level: level.optional(),
    parent_kind: parentFields.parent_kind.optional(),
    parent_value: parentFields.parent_value.optional(),
    conditions: conditions.optional(),
    mitre_ids: mitreIds.optional(),
    frequency: frequency.nullable().optional(),
    timeframe: timeframe.nullable().optional(),
    same_fields: sameFields.optional(),
  })
  .superRefine(checkParent)
  .superRefine((input, ctx) => checkRepetition(input, ctx, { creating: false }))
  .refine((input) => Object.keys(input).length > 0, {
    message: "Provide at least one field to update.",
  });

/** Body of POST /api/wazuh-rules/generate. */
export const generateWazuhRuleSchema = z.strictObject({
  prompt: z
    .string()
    .trim()
    .min(10, "Describe what the rule should detect (at least a sentence).")
    .max(1000, "The description can have at most 1000 characters."),
});

/** Body of POST /api/wazuh-rules/:id/reject. */
export const rejectWazuhRuleSchema = z.strictObject({
  reason: z
    .string()
    .trim()
    .max(500, "The reason can have at most 500 characters.")
    .transform((text) => (text === "" ? null : text))
    .nullable()
    .optional(),
});

export type CreateWazuhRuleInput = z.output<typeof createWazuhRuleSchema>;
export type UpdateWazuhRuleInput = z.output<typeof updateWazuhRuleSchema>;
export type AiWazuhRuleDraft = z.output<typeof aiWazuhRuleSchema>;
