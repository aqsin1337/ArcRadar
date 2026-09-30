/**
 * Wazuh ships example rules 100001 and 100002 in its own local_rules.xml, so a rule ArcRadar creates
 * starts above them. The database check is the wider 100000-999999 (Wazuh's whole custom range).
 */
export const WAZUH_RULE_ID_MIN = 100100;
export const WAZUH_RULE_ID_MAX = 999999;

export const WAZUH_RULE_STATUSES = ["draft", "pushed", "rejected"] as const;
export type WazuhRuleStatus = (typeof WAZUH_RULE_STATUSES)[number];

export const WAZUH_RULE_SOURCES = ["manual", "ai"] as const;
export type WazuhRuleSource = (typeof WAZUH_RULE_SOURCES)[number];

export const WAZUH_RULE_STATUS_LABELS: Record<WazuhRuleStatus, string> = {
  draft: "Draft",
  pushed: "Pushed to GitHub",
  rejected: "Rejected",
};

export const WAZUH_RULE_SOURCE_LABELS: Record<WazuhRuleSource, string> = {
  manual: "Manual",
  ai: "AI-generated",
};

/**
 * A condition is one Wazuh `<field>` test. Only these three comparisons exist: "contains" and
 * "equals" escape the value (so it is always literal text), "regex" takes a pattern that is checked
 * for the constructs that make matching slow or unpredictable (see `checkRegex`).
 */
export const WAZUH_CONDITION_OPS = ["contains", "equals", "regex"] as const;
export type WazuhConditionOp = (typeof WAZUH_CONDITION_OPS)[number];

export const WAZUH_CONDITION_OP_LABELS: Record<WazuhConditionOp, string> = {
  contains: "contains",
  equals: "equals",
  regex: "matches regex",
};

/** Field names Wazuh's Windows decoders produce, offered as suggestions (any name of a known shape is accepted). */
export const WAZUH_FIELD_SUGGESTIONS = [
  "win.system.eventID",
  "win.system.channel",
  "win.eventdata.commandLine",
  "win.eventdata.image",
  "win.eventdata.parentImage",
  "win.eventdata.parentCommandLine",
  "win.eventdata.targetFilename",
  "win.eventdata.targetUserName",
  "win.eventdata.ipAddress",
  "win.eventdata.destinationIp",
  "win.eventdata.user",
] as const;

/** Rule groups a rule can attach to (`<if_group>`); any group of a valid shape is accepted. */
export const WAZUH_GROUP_SUGGESTIONS = [
  "windows",
  "sysmon_event1",
  "sysmon_event3",
  "sysmon_event_11",
  "authentication_failed",
  "syscheck",
] as const;

export const WAZUH_PARENT_KINDS = ["group", "sid"] as const;
export type WazuhParentKind = (typeof WAZUH_PARENT_KINDS)[number];

/** `win.eventdata.commandLine`, `data.srcip`, ...: a known prefix, then dotted name parts. */
export const WAZUH_FIELD_PATTERN = /^(win|data|syscheck|agent)\.[A-Za-z0-9_.-]{1,90}$/;
export const WAZUH_GROUP_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;
export const WAZUH_SID_PATTERN = /^[0-9]{1,7}$/;
export const MITRE_ID_PATTERN = /^T[0-9]{4}(\.[0-9]{3})?$/;

export const MAX_CONDITIONS = 10;
export const MAX_CONDITION_VALUE = 200;

/** The repository layout the Manager-side script relies on: one file per rule, under `rules/`. */
export const wazuhRuleRepoPath = (id: number) => `rules/arcradar_${id}.xml`;
