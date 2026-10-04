import { TimeText } from "@/components/ui/detail-list";
import type { InvestigationTimelineEntry } from "@/lib/investigations/types";
import { personLabel } from "@/lib/format";

const KIND_LABELS: Record<InvestigationTimelineEntry["kind"], string> = {
  opened: "Opened",
  note: "Note",
  system: "Status history",
  evidence: "Evidence",
  indicator: "Indicator",
  alert: "Alert",
};

/** Everything that happened in the investigation, newest first (notes, status changes, attachments). */
export function InvestigationTimeline({ entries }: { entries: InvestigationTimelineEntry[] }) {
  return (
    <ol className="space-y-4 border-l border-border pl-4" aria-label="Timeline">
      {entries.map((entry, index) => (
        <li key={`${entry.kind}-${entry.at}-${index}`} className="relative space-y-0.5">
          <span
            aria-hidden
            className="absolute top-1.5 -left-[21px] size-2 rounded-full border border-border bg-surface-2"
          />
          <p className="text-xs text-muted">
            <span className="sr-only">{KIND_LABELS[entry.kind]}: </span>
            <TimeText iso={entry.at} />
            {entry.actor && <> · {personLabel({ display_name: entry.actor })}</>}
          </p>
          <p className="text-sm font-medium [overflow-wrap:anywhere]">{entry.title}</p>
          {entry.detail && (
            <p className="line-clamp-3 text-xs text-muted [overflow-wrap:anywhere]">
              {entry.detail}
            </p>
          )}
        </li>
      ))}
    </ol>
  );
}
