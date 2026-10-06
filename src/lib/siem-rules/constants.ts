/** SIEMs ArcRadar can write rules for, besides Wazuh (which has its own table and module). */
export const SIEM_IDS = ["splunk"] as const;
export type SiemId = (typeof SIEM_IDS)[number];

export const SIEM_LABELS: Record<SiemId, string> = {
  splunk: "Splunk",
};

export const isSiemId = (value: string): value is SiemId =>
  (SIEM_IDS as readonly string[]).includes(value);

export const SIEM_RULE_STATUSES = ["draft", "pushed", "rejected"] as const;
export type SiemRuleStatus = (typeof SIEM_RULE_STATUSES)[number];

export const SIEM_RULE_SOURCES = ["manual", "ai"] as const;
export type SiemRuleSource = (typeof SIEM_RULE_SOURCES)[number];

export const SIEM_RULE_MODES = ["test", "live"] as const;
export type SiemRuleMode = (typeof SIEM_RULE_MODES)[number];

export const SIEM_RULE_MODE_LABELS: Record<SiemRuleMode, string> = {
  test: "Test mode",
  live: "Live",
};

export const SIEM_RULE_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type SiemRuleSeverity = (typeof SIEM_RULE_SEVERITIES)[number];

export const SIEM_RULE_STATUS_LABELS: Record<SiemRuleStatus, string> = {
  draft: "Draft",
  pushed: "Pushed to GitHub",
  rejected: "Rejected",
};

/** A rule's key names its file in the repository, so it is a plain token. */
export const RULE_KEY_PATTERN = /^[A-Za-z0-9_-]{1,60}$/;

/** Generated keys count up from here (the same idea as Wazuh's 100100 floor). */
export const RULE_KEY_FIRST = 1000;

export const MITRE_ID_PATTERN = /^T[0-9]{4}(\.[0-9]{3})?$/;
