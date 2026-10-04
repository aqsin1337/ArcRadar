import { SearchX } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/states";
import { INDICATOR_TYPE_LABELS } from "@/lib/indicators/constants";
import type { LookupResult } from "@/lib/intel/service";
import { RelatedCard, TimelineCard, WorkspaceCard } from "./local-context";
import { ProfileCard } from "./profile-cards";
import { SourcesCard } from "./sources-card";

/**
 * The outcome of one lookup: what each provider said (labelled demo or live), what happened with
 * every provider, and what the workspace itself knows. Demo data is always announced as such.
 */
export function IntelResult({ result, canAdd }: { result: LookupResult; canAdd: boolean }) {
  const demoOnly =
    result.results.length > 0 && result.results.every((entry) => entry.provider.origin === "demo");
  const tracked = result.local.indicator !== null;

  return (
    <div className="space-y-4" data-testid="intel-result">
      <div className="min-w-0 space-y-2">
        <h2
          className="font-mono text-lg font-semibold [overflow-wrap:anywhere] sm:text-xl"
          data-testid="intel-value"
        >
          {result.value}
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="slate">{INDICATOR_TYPE_LABELS[result.indicator_type]}</Badge>
          <Badge tone={tracked ? "brand" : "slate"}>
            {tracked ? "Tracked in your workspace" : "Not tracked"}
          </Badge>
        </div>
      </div>

      {demoOnly && (
        <Alert tone="warning" title="Demo data">
          {result.fallback
            ? "Live providers are connected, but none of them delivered (see Sources), so this is sample data from the demo dataset, not live intelligence."
            : "This answer comes from the built-in demo dataset, not from a live source. No live intelligence provider is connected to this workspace."}
        </Alert>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          {result.results.length === 0 ? (
            <Card>
              <EmptyState
                icon={SearchX}
                title="No intelligence found"
                description={
                  result.live_providers.length === 0
                    ? "The demo dataset has no record of this value. It only covers a small sample, so this says nothing about whether the value is safe."
                    : "None of the sources has a record of this value. That does not mean it is safe: it may simply be unknown to them."
                }
              />
            </Card>
          ) : (
            result.results.map((entry) => <ProfileCard key={entry.provider.id} result={entry} />)
          )}
          <RelatedCard result={result} />
        </div>
        <div className="min-w-0 space-y-4">
          <WorkspaceCard result={result} canAdd={canAdd} />
          <SourcesCard attempts={result.attempts} />
          <TimelineCard entries={result.local.timeline} tracked={tracked} />
        </div>
      </div>
    </div>
  );
}
