import type { SiemId, SiemRuleSeverity, SiemRuleSource, SiemRuleStatus } from "./constants";

/** What a dialect renders a file from: the part of a rule a person or the AI supplies. */
export type SiemRuleDefinition = {
  rule_key: string;
  name: string;
  description: string | null;
  severity: SiemRuleSeverity;
  mitre_ids: string[];
  /** Validated by the dialect's `specSchema` before it gets here. */
  spec: Record<string, unknown>;
};

/** The file exactly as it would be (or was) committed to the repository. */
export type RenderedRuleFile = { path: string; content: string };

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
};
