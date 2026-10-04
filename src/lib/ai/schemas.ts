import { z } from "zod";
import type { AiAnalysisKind } from "./types";

/**
 * The validated shape of each analysis kind (the table in
 * docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "AI features and where they attach"). A provider is
 * asked for JSON, but only ever trusted once its answer parses against the schema for the kind that
 * was asked: this is what keeps a stored analysis a typed record instead of raw provider text.
 */

export const threatSummarySchema = z.object({
  summary: z.string().trim().min(1).max(2000),
  key_points: z.array(z.string().trim().min(1).max(300)).max(10),
});
export type ThreatSummary = z.output<typeof threatSummarySchema>;

export const attackVectorSchema = z.object({
  techniques: z
    .array(
      z.object({
        id: z.string().trim().min(1).max(20),
        name: z.string().trim().min(1).max(200),
        confidence: z.number().min(0).max(100),
      }),
    )
    .max(10),
  narrative: z.string().trim().min(1).max(2000),
});
export type AttackVector = z.output<typeof attackVectorSchema>;

export const severityValidationSchema = z.object({
  agrees: z.boolean(),
  suggested_severity: z.enum(["info", "low", "medium", "high", "critical"]),
  reasoning: z.string().trim().min(1).max(1000),
});
export type SeverityValidation = z.output<typeof severityValidationSchema>;

export const responseActionsSchema = z.object({
  actions: z
    .array(
      z.object({
        title: z.string().trim().min(1).max(200),
        why: z.string().trim().min(1).max(500),
        urgency: z.enum(["low", "medium", "high", "immediate"]),
      }),
    )
    .min(1)
    .max(8),
});
export type ResponseActions = z.output<typeof responseActionsSchema>;

export const falsePositiveScoreSchema = z.object({
  score: z.number().min(0).max(100),
  reasoning: z.string().trim().min(1).max(1000),
});
export type FalsePositiveScore = z.output<typeof falsePositiveScoreSchema>;

export const investigationChecklistSchema = z.object({
  items: z.array(z.string().trim().min(1).max(300)).min(1).max(20),
});
export type InvestigationChecklist = z.output<typeof investigationChecklistSchema>;

export const verdictRecommendationSchema = z.object({
  verdict: z.enum(["unknown", "benign", "suspicious", "malicious"]),
  confidence: z.number().min(0).max(100),
  reasoning: z.string().trim().min(1).max(1000),
});
export type VerdictRecommendation = z.output<typeof verdictRecommendationSchema>;

export const AI_ANALYSIS_SCHEMAS = {
  threat_summary: threatSummarySchema,
  attack_vector: attackVectorSchema,
  severity_validation: severityValidationSchema,
  response_actions: responseActionsSchema,
  false_positive_score: falsePositiveScoreSchema,
  investigation_checklist: investigationChecklistSchema,
  verdict_recommendation: verdictRecommendationSchema,
} as const satisfies Record<AiAnalysisKind, z.ZodType>;

export type AiAnalysisContent = {
  threat_summary: ThreatSummary;
  attack_vector: AttackVector;
  severity_validation: SeverityValidation;
  response_actions: ResponseActions;
  false_positive_score: FalsePositiveScore;
  investigation_checklist: InvestigationChecklist;
  verdict_recommendation: VerdictRecommendation;
};
