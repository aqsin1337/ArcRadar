import type {
  WazuhConditionOp,
  WazuhParentKind,
  WazuhRuleSource,
  WazuhRuleStatus,
} from "./constants";

export type WazuhRuleCondition = {
  field: string;
  op: WazuhConditionOp;
  value: string;
};

/** What the XML is rendered from. */
export type WazuhRuleDefinition = {
  id: number;
  name: string;
  level: number;
  parent_kind: WazuhParentKind;
  parent_value: string;
  conditions: WazuhRuleCondition[];
  mitre_ids: string[];
  /** Set together: alert when the parent rule matched `frequency` times within `timeframe` seconds. */
  frequency: number | null;
  timeframe: number | null;
  /** Fields that must hold the same value in every counted event. Only with `frequency`. */
  same_fields: string[];
};

export type WazuhRule = WazuhRuleDefinition & {
  description: string | null;
  status: WazuhRuleStatus;
  source: WazuhRuleSource;
  ai_prompt: string | null;
  ai_provider: string | null;
  ai_model: string | null;
  github_path: string | null;
  github_commit: string | null;
  pushed_at: string | null;
  pushed_by: string | null;
  origin: "demo" | "local" | "external";
  changed_since_push: boolean;
  rejected_at: string | null;
  reject_reason: string | null;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
  /** Alerts Wazuh raised through this rule and ArcRadar received. */
  triggers: number;
  last_triggered: string | null;
  /** The file exactly as it would be (or was) committed. */
  xml: string;
};
