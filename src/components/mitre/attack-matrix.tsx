import Link from "next/link";
import { toneClasses, type Tone } from "@/components/ui/badge";
import { cn } from "@/lib/cn";
import { alertListHref } from "@/lib/alerts/url";
import type { Matrix, MatrixTechnique } from "@/lib/mitre/types";
import type { Severity } from "@/types/domain";

/** How serious the worst alert naming a technique was, as the color of its cell. The count is always written too. */
const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: "red",
  high: "red",
  medium: "orange",
  low: "blue",
  info: "blue",
};

function describe(technique: MatrixTechnique): string {
  const seen = technique.observed;
  if (!seen) return "not seen in any alert";
  return `seen in ${seen.alert_count} ${seen.alert_count === 1 ? "alert" : "alerts"}, worst severity ${seen.max_severity}`;
}

/** An observed technique opens the alerts that name it; any other opens its reference page. */
function hrefFor(technique: MatrixTechnique): string {
  return technique.observed
    ? alertListHref({}, { technique: technique.id })
    : `/mitre/${technique.id}`;
}

function Cell({ technique, sub = false }: { technique: MatrixTechnique; sub?: boolean }) {
  const seen = technique.observed;
  return (
    <Link
      href={hrefFor(technique)}
      data-observed={seen ? "true" : "false"}
      className={cn(
        "flex items-start justify-between gap-2 rounded-md border px-2 py-1.5 text-left text-xs leading-snug transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring",
        seen
          ? cn(toneClasses(SEVERITY_TONE[seen.max_severity]), "font-medium hover:brightness-110")
          : "border-border bg-surface text-muted hover:border-input-border hover:text-foreground",
        sub && "ml-3",
      )}
    >
      <span className="min-w-0 [overflow-wrap:anywhere]">
        <span className="font-mono">{technique.id}</span> {technique.name}
        <span className="sr-only">, {describe(technique)}</span>
      </span>
      {seen && (
        <span
          aria-hidden
          className="shrink-0 rounded-full border border-current px-1.5 text-[0.7rem] leading-4"
        >
          {seen.alert_count}
        </span>
      )}
    </Link>
  );
}

/**
 * The ATT&CK matrix: a column per tactic, in the order of an attack, and the techniques under it.
 * Techniques the workspace's alerts named are colored by the worst severity and carry their alert
 * count; a click opens those alerts. It scrolls sideways on a narrow screen instead of squeezing.
 */
export function AttackMatrix({
  matrix,
  showSubtechniques,
}: {
  matrix: Matrix;
  showSubtechniques: boolean;
}) {
  return (
    <div
      role="region"
      aria-label="ATT&CK matrix, scrolls sideways"
      tabIndex={0}
      className="relative overflow-x-auto rounded-xl border border-border bg-surface p-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
    >
      <ol className="flex min-w-max gap-2">
        {matrix.tactics.map((tactic) => (
          <li key={tactic.name} className="w-56 shrink-0">
            <h2 className="rounded-md bg-surface-2 px-2 py-2 text-sm font-semibold">
              {tactic.name}
              <span className="mt-0.5 block text-xs font-normal text-muted">
                {tactic.techniques.length}{" "}
                {tactic.techniques.length === 1 ? "technique" : "techniques"}
                {tactic.observed_techniques > 0 && ` · ${tactic.observed_techniques} seen`}
              </span>
            </h2>
            <ul aria-label={`${tactic.name} techniques`} className="mt-2 space-y-1.5">
              {tactic.techniques.map((technique) => (
                <li key={technique.id} className="space-y-1.5">
                  <Cell technique={technique} />
                  {showSubtechniques &&
                    technique.subtechniques.map((sub) => <Cell key={sub.id} technique={sub} sub />)}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>
    </div>
  );
}
