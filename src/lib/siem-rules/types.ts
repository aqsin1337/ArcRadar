import type {
  SiemId,
  SiemRuleMode,
  SiemRuleSeverity,
  SiemRuleSource,
  SiemRuleStatus,
} from "./constants";

/** What a dialect renders a file from: the part of a rule a person or the AI supplies. */
export type SiemRuleDefinition = {
  rule_key: string;
  name: string;
  description: string | null;
  severity: SiemRuleSeverity;
  /** Test: the file is loaded but never runs on a schedule and has no action. Live: the rule as written. */
  mode: SiemRuleMode;
  mitre_ids: string[];
  /** Validated by the dialect's `specSchema` before it gets here. */
  spec: Record<string, unknown>;
};

/** The file exactly as it would be (or was) committed to the repository. */
export type RenderedRuleFile = { path: string; content: string };

/** One example a backtest found. */
export type BacktestSample = {
  time?: string;
  count?: number;
  group?: Record<string, string | number>;
};

/** What the SIEM host found when it ran a rule's search over past data. */
export type RuleBacktest = {
  window_hours: 24 | 168;
  /** threshold: matches counts the (time bucket, group) pairs over the limit; events: matches counts events. */
  kind: "threshold" | "events";
  matches: number;
  scanned: number | null;
  sample: BacktestSample[];
  error: string | null;
  reported_at: string;
  /** The rule's search changed after this was measured: the result is for an older version. */
  stale: boolean;
};

export type SiemRule = SiemRuleDefinition & {
  id: string;
  siem: SiemId;
  status: SiemRuleStatus;
  source: SiemRuleSource;
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
  file: RenderedRuleFile;
  backtests: RuleBacktest[];
};
