import type { DataOrigin, Severity } from "@/types/domain";
import type { DetectionRuleField, DetectionRuleOp } from "./constants";

export type DetectionRuleCondition = {
  field: DetectionRuleField;
  op: DetectionRuleOp;
  value: string;
};

/** A curated, admin-managed rule, evaluated inline against every alert as it is created. */
export type DetectionRule = {
  id: number;
  name: string;
  description: string | null;
  conditions: DetectionRuleCondition[];
  /** Raises a matching alert's severity (never lowers it); null means "trace it, don't override". */
  severity: Severity | null;
  priority: number;
  enabled: boolean;
  origin: DataOrigin;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
};
