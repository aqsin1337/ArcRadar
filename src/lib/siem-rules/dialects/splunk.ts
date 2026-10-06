import { z } from "zod";
import { escapeRegex } from "@/lib/wazuh-rules/xml";
import { checkRegex } from "@/lib/wazuh-rules/schema";
import type { RuleDialect } from "../dialect";
import type { RenderedRuleFile, SiemRuleDefinition } from "../types";

/**
 * Splunk dialect. A rule is stored as structured fields and ArcRadar renders one `savedsearches.conf`
 * stanza from a FIXED template: `search index=... | regex ... [| stats count by ... | where count >= N]`.
 * Nothing a caller or the AI writes is ever placed in the file as SPL: values only ever appear inside a
 * quoted, escaped string; index, sourcetype and field names are matched against strict patterns; and the
 * finished search is checked again (`assertSafeSplunkConf`) so only `search`, `regex`, `stats` and `where`
 * can be in it. `| outputlookup`, `| sendalert`, `| script`, `| collect`, `| delete`, `| map`, `| rest` and
 * every other command are impossible by construction, not by a blocklist.
 */

export const SPLUNK_CONDITION_OPS = ["contains", "equals", "regex"] as const;
export type SplunkConditionOp = (typeof SPLUNK_CONDITION_OPS)[number];

export const SPLUNK_SCHEDULES = {
  every_5_minutes: { label: "Every 5 minutes", cron: "*/5 * * * *", minutes: 5 },
  every_15_minutes: { label: "Every 15 minutes", cron: "*/15 * * * *", minutes: 15 },
  hourly: { label: "Every hour", cron: "0 * * * *", minutes: 60 },
  daily: { label: "Every day at 06:00", cron: "0 6 * * *", minutes: 1440 },
} as const;
export type SplunkSchedule = keyof typeof SPLUNK_SCHEDULES;

/** Splunk's `alert.severity`: 2 info, 3 warning, 4 error, 5 severe. */
const SEVERITY_NUMBER = { low: 2, medium: 3, high: 4, critical: 5 } as const;

export const SPLUNK_FIELD_SUGGESTIONS = [
  "EventCode",
  "CommandLine",
  "Image",
  "ParentImage",
  "ParentCommandLine",
  "TargetFilename",
  "TargetUserName",
  "Account_Name",
  "Source_Network_Address",
  "src_ip",
  "dest_ip",
  "user",
] as const;

export const SPLUNK_SOURCETYPE_SUGGESTIONS = [
  "WinEventLog:Security",
  "WinEventLog:System",
  "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
] as const;

export const MAX_SPLUNK_CONDITIONS = 10;
export const MAX_SPLUNK_VALUE = 200;
export const MAX_SPLUNK_BY_FIELDS = 3;

const INDEX_PATTERN = /^[a-z0-9_][a-z0-9_-]{0,59}$/;
const SOURCETYPE_PATTERN = /^[A-Za-z0-9_:./-]{1,80}$/;
const FIELD_PATTERN = /^[A-Za-z_][A-Za-z0-9_.]{0,79}$/;

/** What ends up inside a quoted SPL string. `$` is refused (Splunk reads `$x$` as a token). */
const FORBIDDEN_IN_VALUE = /[\u0000-\u001f\u007f$]/;

const fieldName = z
  .string()
  .trim()
  .regex(FIELD_PATTERN, "Use a Splunk field name such as CommandLine (letters, digits, _ and .).");

const condition = z
  .strictObject({
    field: fieldName,
    op: z.enum(SPLUNK_CONDITION_OPS),
    value: z
      .string()
      .min(1, "Enter a value.")
      .max(MAX_SPLUNK_VALUE, `The value can have at most ${MAX_SPLUNK_VALUE} characters.`)
      .refine(
        (text) => !FORBIDDEN_IN_VALUE.test(text),
        "The value cannot contain control characters or the $ character.",
      ),
  })
  .superRefine((input, ctx) => {
    if (input.op !== "regex") return;
    const problem = checkRegex(input.value);
    if (problem) ctx.addIssue({ code: "custom", path: ["value"], message: problem });
  });

const threshold = z.strictObject({
  count: z
    .number()
    .int({ error: "The count must be a whole number." })
    .min(2, "The count is 2 to 1000.")
    .max(1000, "The count is 2 to 1000."),
  window_minutes: z
    .number()
    .int({ error: "The window must be a whole number of minutes." })
    .min(1, "The window is 1 to 1440 minutes.")
    .max(1440, "The window is 1 to 1440 minutes."),
  by: z
    .array(fieldName)
    .max(MAX_SPLUNK_BY_FIELDS, `At most ${MAX_SPLUNK_BY_FIELDS} fields.`)
    .transform((fields) => [...new Set(fields)]),
});

export const splunkSpecSchema = z
  .strictObject({
    index: z
      .string()
      .trim()
      .regex(INDEX_PATTERN, "Use an index name such as main (lowercase letters, digits, _ and -)."),
    sourcetype: z
      .string()
      .trim()
      .regex(SOURCETYPE_PATTERN, "Use a sourcetype such as WinEventLog:Security.")
      .nullable()
      .default(null),
    conditions: z
      .array(condition)
      .max(MAX_SPLUNK_CONDITIONS, `A rule can have at most ${MAX_SPLUNK_CONDITIONS} conditions.`)
      .default([]),
    threshold: threshold.nullable().default(null),
    schedule: z
      .enum(Object.keys(SPLUNK_SCHEDULES) as [SplunkSchedule, ...SplunkSchedule[]])
      .default("every_5_minutes"),
  })
  .superRefine((input, ctx) => {
    if (input.conditions.length === 0 && input.threshold === null) {
      ctx.addIssue({
        code: "custom",
        path: ["conditions"],
        message: "Add at least one condition, or make this a repeating rule.",
      });
    }
  });

export type SplunkSpec = z.output<typeof splunkSpecSchema>;

/** `"..."` with `\` and `"` escaped: the only way a value ever enters the search. */
export function splQuote(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** The regex a condition becomes. Always case-insensitive: Windows paths and switches vary in case. */
export function splunkConditionPattern(op: SplunkConditionOp, value: string): string {
  if (op === "contains") return `(?i)${escapeRegex(value)}`;
  if (op === "equals") return `(?i)^${escapeRegex(value)}$`;
  return `(?i)${value}`;
}

export function buildSplunkSearch(spec: SplunkSpec): string {
  const head = [`search index=${spec.index}`];
  if (spec.sourcetype) head.push(`sourcetype=${spec.sourcetype}`);
  const parts = [head.join(" ")];
  for (const item of spec.conditions) {
    parts.push(`regex ${item.field}=${splQuote(splunkConditionPattern(item.op, item.value))}`);
  }
  if (spec.threshold) {
    const by = spec.threshold.by.length > 0 ? ` by ${spec.threshold.by.join(", ")}` : "";
    parts.push(`stats count${by}`, `where count >= ${spec.threshold.count}`);
  }
  return parts.join(" | ");
}

const ALLOWED_COMMANDS = new Set(["search", "regex", "stats", "where"]);

/** Splits an SPL pipeline on `|` outside quoted strings. */
export function splitPipeline(search: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < search.length; i += 1) {
    const char = search[i];
    if (quoted) {
      current += char;
      if (char === "\\") {
        current += search[i + 1] ?? "";
        i += 1;
      } else if (char === '"') quoted = false;
    } else if (char === '"') {
      quoted = true;
      current += char;
    } else if (char === "|") {
      segments.push(current.trim());
      current = "";
    } else current += char;
  }
  segments.push(current.trim());
  return segments;
}

const CONF_KEYS = new Set([
  "description",
  "search",
  "enableSched",
  "cron_schedule",
  "dispatch.earliest_time",
  "dispatch.latest_time",
  "alert_type",
  "alert_comparator",
  "alert_threshold",
  "alert.severity",
  "alert.track",
  "alert.digest_mode",
  "alert.suppress",
  "alert.suppress.period",
  "alert.suppress.fields",
  "action.arcradar_forward",
  "action.arcradar_forward.param.rule_key",
  "action.arcradar_forward.param.name",
  "action.arcradar_forward.param.severity",
  "action.arcradar_forward.param.mitre",
]);

/**
 * The renderer's own check of what it produced: one stanza named for the rule, only the keys of the
 * template, a single-line search made only of allowed commands. Throws if anything else is present.
 * The apply script on the Splunk host repeats the same check, so a file edited on GitHub is refused too.
 */
export function assertSafeSplunkConf(content: string, ruleKey: string): void {
  const lines = content.split("\n").filter((line) => line !== "");
  let stanzas = 0;
  for (const line of lines) {
    if (line.startsWith("# ")) continue;
    if (line.startsWith("[")) {
      if (line !== `[arcradar_${ruleKey}]`) throw new Error("Unexpected stanza in a Splunk rule.");
      stanzas += 1;
      continue;
    }
    const match = /^([A-Za-z0-9_.]+) = (.*)$/.exec(line);
    if (!match || !CONF_KEYS.has(match[1])) throw new Error("Unexpected setting in a Splunk rule.");
    if (match[1] === "search") {
      const [first, ...rest] = splitPipeline(match[2]);
      if (!first.startsWith("search "))
        throw new Error("A Splunk rule search must start with search.");
      for (const segment of rest) {
        const command = segment.split(/\s+/, 1)[0];
        if (!ALLOWED_COMMANDS.has(command)) {
          throw new Error(`Command "${command}" is not allowed in a Splunk rule.`);
        }
      }
    }
    if (match[2].endsWith("\\")) throw new Error("A setting cannot end with a backslash.");
  }
  if (stanzas !== 1) throw new Error("A Splunk rule file has exactly one stanza.");
}

export const splunkRulePath = (ruleKey: string) => `splunk/arcradar_${ruleKey}.conf`;

function renderSplunkRule(rule: SiemRuleDefinition): RenderedRuleFile {
  const spec = splunkSpecSchema.parse(rule.spec);
  const schedule = SPLUNK_SCHEDULES[spec.schedule];
  const window = spec.threshold?.window_minutes ?? schedule.minutes;
  const lines = [
    `# ArcRadar rule ${rule.rule_key}. Generated by ArcRadar: change it there, not in this file.`,
    `[arcradar_${rule.rule_key}]`,
    `description = ${rule.name}`,
    `search = ${buildSplunkSearch(spec)}`,
    `enableSched = 1`,
    `cron_schedule = ${schedule.cron}`,
    `dispatch.earliest_time = -${window}m`,
    `dispatch.latest_time = now`,
    `alert_type = number of events`,
    `alert_comparator = greater than`,
    `alert_threshold = 0`,
    `alert.severity = ${SEVERITY_NUMBER[rule.severity as keyof typeof SEVERITY_NUMBER]}`,
    `alert.track = 1`,
    `alert.digest_mode = 0`,
  ];
  if (spec.threshold) {
    // One alert per group per window, not one per run.
    lines.push(`alert.suppress = 1`, `alert.suppress.period = ${window}m`);
    if (spec.threshold.by.length > 0) {
      lines.push(`alert.suppress.fields = ${spec.threshold.by.join(",")}`);
    }
  }
  lines.push(
    `action.arcradar_forward = 1`,
    `action.arcradar_forward.param.rule_key = ${rule.rule_key}`,
    `action.arcradar_forward.param.name = ${rule.name}`,
    `action.arcradar_forward.param.severity = ${rule.severity}`,
  );
  if (rule.mitre_ids.length > 0) {
    lines.push(`action.arcradar_forward.param.mitre = ${rule.mitre_ids.join(",")}`);
  }
  lines.push("");
  const content = lines.join("\n");
  assertSafeSplunkConf(content, rule.rule_key);
  return { path: splunkRulePath(rule.rule_key), content };
}

export const SPLUNK_RULE_PROMPT_VERSION = 1;

const SYSTEM_PROMPT = `You write Splunk detection rules for Windows 10 event logs, for a security analyst who
will review your draft before anything is used. You are given a description of what to detect.

Rules:
- Reply with one JSON object and nothing else: no markdown, no code fences, no text before or after it.
- Shape: { "name": string (a short title, at most 100 characters, no $ or backslash), "description": string
  (1-2 sentences: what the rule detects and why it matters), "severity": "low"|"medium"|"high"|"critical",
  "mitre_ids": string[] (0-3 ATT&CK technique ids such as "T1562.001"), "spec": { "index": string,
  "sourcetype": string or null, "conditions": [{ "field": string, "op": "contains"|"equals"|"regex",
  "value": string }] (0-4 conditions, all must match), "threshold": null or { "count": integer 2-1000,
  "window_minutes": integer 1-1440, "by": string[] (0-2 fields to group by) }, "schedule":
  "every_5_minutes"|"every_15_minutes"|"hourly"|"daily" } }.
- You do NOT write SPL. ArcRadar builds the search from "spec". Never put a search command, a pipe or a
  macro in any value.
- "index" is normally "main". "sourcetype" examples: ${SPLUNK_SOURCETYPE_SUGGESTIONS.join(", ")}; use null
  when the request does not say.
- Field names are Splunk field names such as ${SPLUNK_FIELD_SUGGESTIONS.join(", ")}. Windows failed logon is
  EventCode 4625 on WinEventLog:Security; process creation is EventCode 1 in Sysmon.
- REPEATING rules: when the request is about something happening several times in a period ("5 failed
  logons in 5 minutes from one address"), set "threshold" to { "count", "window_minutes", "by" } where "by"
  holds the field that must be the same (for example "Source_Network_Address" or "Account_Name"), and
  keep "conditions" for the single event being counted. For a rule on a single event set "threshold" to null.
- A rule needs at least one condition unless it has a threshold.
- Prefer "contains" for a literal piece of text. Use "regex" only when a literal cannot express it, and
  keep the pattern simple: no lookarounds, no back-references, no nested repetition, no "$". Matching is
  case-insensitive already; do not add flags such as (?i).
- A rule only detects. Never add anything that changes a system or sends data elsewhere.
- Only use a MITRE id you are confident matches the behaviour; an empty list is fine.
- Base the rule only on the description; do not invent hosts, paths or users it does not mention.`;

export const splunkDialect: RuleDialect = {
  siem: "splunk",
  label: "Splunk",
  specSchema: splunkSpecSchema,
  render: renderSplunkRule,
  prompt: {
    version: SPLUNK_RULE_PROMPT_VERSION,
    maxOutputTokens: 700,
    build: (description) => ({ system: SYSTEM_PROMPT, user: `Detect this:\n${description}` }),
  },
};
