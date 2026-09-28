/**
 * The rule id range mirrors Wazuh's own custom-rule id space, chosen so the two number ranges never
 * collide (an id here can correlate 1:1 with a rule of the same number on the Manager, if wanted).
 */
export const DETECTION_RULE_ID_MIN = 100000;
export const DETECTION_RULE_ID_MAX = 999999;

/**
 * A fixed, closed grammar (never a filter built from free text): the only fields a condition may
 * name. `detection_rule_matches()` in the database is the authority; this list, and the field/op
 * pairs below, only exist so the UI never offers a combination the database would fail closed on.
 */
export const DETECTION_RULE_FIELDS = [
  "title",
  "description",
  "source",
  "severity",
  "technique_id",
] as const;
export type DetectionRuleField = (typeof DETECTION_RULE_FIELDS)[number];

export const DETECTION_RULE_OPS = ["eq", "contains"] as const;
export type DetectionRuleOp = (typeof DETECTION_RULE_OPS)[number];

export const DETECTION_RULE_FIELD_LABELS: Record<DetectionRuleField, string> = {
  title: "Title",
  description: "Description",
  source: "Source",
  severity: "Severity",
  technique_id: "MITRE technique",
};

export const DETECTION_RULE_OP_LABELS: Record<DetectionRuleOp, string> = {
  eq: "is",
  contains: "contains",
};

/** Which comparisons each field supports. */
export const DETECTION_RULE_FIELD_OPS: Record<DetectionRuleField, readonly DetectionRuleOp[]> = {
  severity: ["eq"],
  source: ["eq", "contains"],
  title: ["contains"],
  description: ["contains"],
  technique_id: ["eq"],
};
