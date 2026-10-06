import { z } from "zod";
import type { RuleDialect } from "./dialect";
import {
  MITRE_ID_PATTERN,
  RULE_KEY_PATTERN,
  SIEM_RULE_MODES,
  SIEM_RULE_SEVERITIES,
} from "./constants";

/**
 * The SIEM-independent part of a rule. The name ends up in a file a SIEM parses line by line, so it
 * cannot hold control characters, a backslash (a trailing one continues the line in a .conf file) or `$`.
 */
const name = z
  .string()
  .trim()
  .min(1, "Enter a name.")
  .max(200, "The name can have at most 200 characters.")
  .refine(
    (text) => !/[\u0000-\u001f\u007f\\$]/.test(text),
    "The name cannot contain control characters, a backslash or the $ character.",
  );

const description = z
  .string()
  .trim()
  .max(2000, "The description can have at most 2000 characters.")
  .transform((text) => (text === "" ? null : text))
  .nullable();

const severity = z.enum(SIEM_RULE_SEVERITIES);

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

const ruleKey = z
  .string()
  .trim()
  .regex(RULE_KEY_PATTERN, "Use letters, digits, _ and - only (at most 60 characters).");

/** What a person or the AI supplies for one SIEM. No id, status, source or origin here. */
function definitionShape(dialect: RuleDialect) {
  return {
    name,
    description: description.optional(),
    severity,
    mitre_ids: mitreIds.default([]),
    spec: dialect.specSchema,
  };
}

/** Body of POST /api/siem-rules/:siem. `rule_key` is optional: the server picks the next free one. */
export const createSiemRuleSchema = (dialect: RuleDialect) =>
  z.strictObject({ rule_key: ruleKey.optional(), ...definitionShape(dialect) });

/** What the AI must return (same rules, so an answer that breaks one is refused, never stored). */
export const aiSiemRuleSchema = (dialect: RuleDialect) => z.object(definitionShape(dialect));

/** Body of PATCH. A `spec` replaces the whole spec. The key and the SIEM cannot change. */
export const updateSiemRuleSchema = (dialect: RuleDialect) =>
  z
    .strictObject({
      name: name.optional(),
      description: description.optional(),
      severity: severity.optional(),
      mitre_ids: mitreIds.optional(),
      spec: dialect.specSchema.optional(),
    })
    .refine((input) => Object.keys(input).length > 0, {
      message: "Provide at least one field to update.",
    });

export const generateSiemRuleSchema = z.strictObject({
  prompt: z
    .string()
    .trim()
    .min(10, "Describe what the rule should detect (at least a sentence).")
    .max(1000, "The description can have at most 1000 characters."),
});

/** Query of POST .../push: `?mode=test` pushes the rule in test mode; no mode means live. */
export const pushSiemRuleQuerySchema = z.object({ mode: z.enum(SIEM_RULE_MODES).default("live") });

export const rejectSiemRuleSchema = z.strictObject({
  reason: z
    .string()
    .trim()
    .max(500, "The reason can have at most 500 characters.")
    .transform((text) => (text === "" ? null : text))
    .nullable()
    .optional(),
});

export type CreateSiemRuleInput = {
  rule_key?: string;
  name: string;
  description?: string | null;
  severity: (typeof SIEM_RULE_SEVERITIES)[number];
  mitre_ids: string[];
  spec: Record<string, unknown>;
};
export type UpdateSiemRuleInput = Partial<Omit<CreateSiemRuleInput, "rule_key">>;
