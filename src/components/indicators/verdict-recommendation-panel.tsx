"use client";

import { Sparkles } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { VerdictBadge } from "@/components/ui/domain-badges";
import { apiFetch } from "@/lib/api/client";
import { formatRelative } from "@/lib/format";
import type { VerdictRecommendation } from "@/lib/ai/schemas";
import type { AiAnalysisRecord } from "@/lib/ai/types";
import type { Verdict } from "@/types/domain";

/**
 * A recommendation only: applying it is a normal, audited `PATCH /api/indicators/:id` the analyst
 * triggers themselves with the button below — the AI never changes the indicator's verdict itself.
 */
export function VerdictRecommendationPanel({
  indicatorId,
  canUse,
  canApply,
  ready,
  initial,
  now,
}: {
  indicatorId: string;
  canUse: boolean;
  canApply: boolean;
  ready: boolean;
  initial: AiAnalysisRecord | null;
  now: Date;
}) {
  const router = useRouter();
  const [latest, setLatest] = useState(initial);
  const [pending, setPending] = useState<"ask" | "apply" | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!canUse && !latest) return null;
  const content = latest ? (latest.content as VerdictRecommendation) : null;

  async function ask() {
    setPending("ask");
    setError(null);
    const result = await apiFetch<AiAnalysisRecord>(`/api/indicators/${indicatorId}/ai`, {
      body: { kind: "verdict_recommendation" },
    });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setLatest(result.data);
  }

  async function apply() {
    if (!content) return;
    setPending("apply");
    setError(null);
    const result = await apiFetch(`/api/indicators/${indicatorId}`, {
      method: "PATCH",
      body: { verdict: content.verdict, confidence: Math.round(content.confidence) },
    });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="space-y-3" data-testid="verdict-recommendation-panel">
      {error && <Alert tone="error">{error}</Alert>}

      {canUse && ready && (
        <Button
          type="button"
          variant="secondary"
          size="sm"
          loading={pending === "ask"}
          disabled={pending !== null}
          onClick={ask}
        >
          <Sparkles aria-hidden className="size-4" />
          {content ? "Re-run" : "Ask AI"}
        </Button>
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

      {content && latest ? (
        <div className="space-y-2 rounded-lg border border-border p-3">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictBadge verdict={content.verdict as Verdict} />
            <Badge tone="slate">{Math.round(content.confidence)}% confidence</Badge>
            <Badge tone="violet" dashed>
              AI-generated — analyst-assisted
            </Badge>
          </div>
          <p className="text-sm leading-relaxed">{content.reasoning}</p>
          <p className="text-xs text-muted">
            {latest.provider} · {latest.model} · {formatRelative(latest.created_at, now)}
          </p>
          {canApply && (
            <Button
              type="button"
              size="sm"
              loading={pending === "apply"}
              disabled={pending !== null}
              onClick={apply}
            >
              Apply this verdict
            </Button>
          )}
        </div>
      ) : (
        <p className="text-sm text-muted">No AI recommendation yet.</p>
      )}
    </div>
  );
}
