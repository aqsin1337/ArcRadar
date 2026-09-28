"use client";

import { Crosshair, Gauge, ListChecks, Percent, Sparkles } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/domain-badges";
import { apiFetch } from "@/lib/api/client";
import { formatRelative } from "@/lib/format";
import type {
  AttackVector,
  FalsePositiveScore,
  ResponseActions,
  SeverityValidation,
  ThreatSummary,
} from "@/lib/ai/schemas";
import type { AiAnalysisRecord } from "@/lib/ai/types";

/** This card only ever shows the five alert-page kinds; investigation and indicator kinds have their
 * own panels (`ChecklistPanel`, `VerdictRecommendationPanel`). */
type AlertAnalysisKind =
  | "threat_summary"
  | "attack_vector"
  | "severity_validation"
  | "response_actions"
  | "false_positive_score";

const URGENCY_TONES: Record<ResponseActions["actions"][number]["urgency"], Tone> = {
  low: "slate",
  medium: "amber",
  high: "orange",
  immediate: "red",
};

const KIND_CONFIG: Record<AlertAnalysisKind, { label: string; icon: typeof Sparkles }> = {
  threat_summary: { label: "Summarize", icon: Sparkles },
  attack_vector: { label: "Map ATT&CK techniques", icon: Crosshair },
  severity_validation: { label: "Validate severity", icon: Gauge },
  response_actions: { label: "Suggest response actions", icon: ListChecks },
  false_positive_score: { label: "Score false positive", icon: Percent },
};

const KIND_ORDER: AlertAnalysisKind[] = [
  "threat_summary",
  "attack_vector",
  "severity_validation",
  "false_positive_score",
  "response_actions",
];

function AnalysisBody({ kind, content }: { kind: AlertAnalysisKind; content: unknown }) {
  switch (kind) {
    case "threat_summary": {
      const c = content as ThreatSummary;
      return (
        <div className="space-y-2">
          <p className="text-sm leading-relaxed">{c.summary}</p>
          {c.key_points.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
              {c.key_points.map((point, index) => (
                <li key={index}>{point}</li>
              ))}
            </ul>
          )}
        </div>
      );
    }
    case "attack_vector": {
      const c = content as AttackVector;
      return (
        <div className="space-y-2">
          {c.techniques.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {c.techniques.map((technique) => (
                <Badge key={technique.id} tone="violet">
                  {technique.id} {technique.name} · {Math.round(technique.confidence)}%
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted">
              No specific technique stood out from this alert&apos;s data.
            </p>
          )}
          <p className="text-sm leading-relaxed">{c.narrative}</p>
        </div>
      );
    }
    case "severity_validation": {
      const c = content as SeverityValidation;
      return (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Badge tone={c.agrees ? "green" : "amber"}>
              {c.agrees ? "Agrees with current severity" : "Suggests a different severity"}
            </Badge>
            {!c.agrees && <SeverityBadge severity={c.suggested_severity} />}
          </div>
          <p className="text-sm leading-relaxed">{c.reasoning}</p>
        </div>
      );
    }
    case "response_actions": {
      const c = content as ResponseActions;
      return (
        <ul className="space-y-2">
          {c.actions.map((action, index) => (
            <li key={index} className="flex flex-wrap items-start gap-2 text-sm">
              <Badge tone={URGENCY_TONES[action.urgency]} className="mt-0.5 shrink-0">
                {action.urgency}
              </Badge>
              <span>
                <span className="font-medium">{action.title}</span>
                <span className="block text-muted">{action.why}</span>
              </span>
            </li>
          ))}
        </ul>
      );
    }
    case "false_positive_score": {
      const c = content as FalsePositiveScore;
      const tone: Tone = c.score >= 70 ? "green" : c.score >= 40 ? "amber" : "red";
      return (
        <div className="space-y-2">
          <Badge tone={tone} className="text-sm">
            {Math.round(c.score)}% likely a false positive
          </Badge>
          <p className="text-sm leading-relaxed">{c.reasoning}</p>
        </div>
      );
    }
  }
}

/**
 * AI-assisted analysis for one alert: five "ask AI" actions, each rendering the latest answer of its
 * kind in a clearly labelled, immutable card next to the alert's real fields — never in place of them.
 * Anyone who can read the alert sees analyses already generated for it; only `canUse` can ask for more.
 */
export function AiAnalysisPanel({
  alertId,
  canUse,
  ready,
  initialLatest,
  now,
}: {
  alertId: string;
  canUse: boolean;
  ready: boolean;
  initialLatest: Partial<Record<AlertAnalysisKind, AiAnalysisRecord>>;
  now: Date;
}) {
  const router = useRouter();
  const [latest, setLatest] = useState(initialLatest);
  const [pending, setPending] = useState<AlertAnalysisKind | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function ask(kind: AlertAnalysisKind) {
    if (pending) return;
    setPending(kind);
    setError(null);
    const result = await apiFetch<AiAnalysisRecord>(`/api/alerts/${alertId}/ai`, {
      body: { kind },
    });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setLatest((current) => ({ ...current, [kind]: result.data }));
    // Response actions also seed the separate, server-rendered response-action log: bring it up to
    // date too, alongside this card's own instant local update.
    if (kind === "response_actions") router.refresh();
  }

  const cards = KIND_ORDER.filter((kind) => latest[kind]);

  if (cards.length === 0 && !canUse) return null;

  return (
    <Card data-testid="ai-analysis-panel">
      <CardHeader>
        <CardTitle>AI analysis</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <Alert tone="error">{error}</Alert>}

        {canUse && ready && (
          <div className="flex flex-wrap gap-2">
            {KIND_ORDER.map((kind) => {
              const { label, icon: Icon } = KIND_CONFIG[kind];
              return (
                <Button
                  key={kind}
                  type="button"
                  variant="secondary"
                  size="sm"
                  loading={pending === kind}
                  disabled={pending !== null}
                  onClick={() => ask(kind)}
                >
                  <Icon aria-hidden className="size-4" />
                  {latest[kind] ? `Re-run: ${label}` : label}
                </Button>
              );
            })}
          </div>
        )}
        {canUse && !ready && (
          <p className="text-sm text-muted">
            No AI provider is configured. Ask an administrator to set one up on the{" "}
            <Link href="/integrations" className="underline underline-offset-2">
              Integrations
            </Link>{" "}
            page.
          </p>
        )}

        {cards.length === 0 ? (
          <p className="text-sm text-muted">
            No AI analysis has been generated for this alert yet.
          </p>
        ) : (
          <div className="space-y-4">
            {cards.map((kind) => {
              const analysis = latest[kind];
              if (!analysis) return null;
              return (
                <div key={kind} className="space-y-2 rounded-lg border border-border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-medium">{KIND_CONFIG[kind].label}</p>
                    <Badge tone="violet" dashed>
                      AI-generated — analyst-assisted
                    </Badge>
                  </div>
                  <AnalysisBody kind={kind} content={analysis.content} />
                  <p className="text-xs text-muted">
                    {analysis.provider} · {analysis.model} ·{" "}
                    {formatRelative(analysis.created_at, now)}
                  </p>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
