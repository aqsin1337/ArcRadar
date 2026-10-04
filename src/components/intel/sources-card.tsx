import { Badge, type Tone } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { OriginBadge } from "@/components/ui/domain-badges";
import { describeAttempt } from "@/lib/intel/messages";
import type { ProviderAttempt } from "@/lib/intel/types";

const STATUS: Record<ProviderAttempt["status"], { label: string; tone: Tone }> = {
  ok: { label: "Answered", tone: "green" },
  not_found: { label: "No record", tone: "slate" },
  skipped: { label: "Not asked", tone: "slate" },
  failed: { label: "Failed", tone: "amber" },
};

/** Which providers were considered for this lookup and what each one did: nothing is hidden. */
export function SourcesCard({ attempts }: { attempts: ProviderAttempt[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Sources</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-border">
          {attempts.map((attempt) => (
            <li key={attempt.provider.id} className="space-y-1 py-2.5 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">{attempt.provider.name}</span>
                <OriginBadge origin={attempt.provider.origin} />
                <Badge tone={STATUS[attempt.status].tone} className="ml-auto">
                  {STATUS[attempt.status].label}
                </Badge>
              </div>
              <p className="text-xs text-muted">{describeAttempt(attempt)}</p>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
