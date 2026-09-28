import { cn } from "@/lib/cn";
import { totalEngines } from "@/lib/intel/providers/common";
import type { Detections } from "@/lib/intel/types";

const SEGMENTS = [
  { key: "malicious", label: "Malicious", fill: "bg-tone-red-fg" },
  { key: "suspicious", label: "Suspicious", fill: "bg-tone-amber-fg" },
  { key: "harmless", label: "Harmless", fill: "bg-tone-green-fg" },
  { key: "undetected", label: "Undetected", fill: "bg-tone-slate-fg" },
] as const;

/**
 * How many analysis engines reached each conclusion: a proportion bar (2px gaps between segments)
 * plus the four counts as text. The counts carry the meaning, so nothing depends on telling the
 * colors apart; the bar has a text alternative that says the same.
 */
export function DetectionBar({ detections }: { detections: Detections }) {
  const total = totalEngines(detections);
  if (total === 0) return <p className="text-sm text-muted">No engine results.</p>;

  const summary = SEGMENTS.map(
    ({ key, label }) => `${detections[key]} ${label.toLowerCase()}`,
  ).join(", ");

  return (
    <div>
      <div
        role="img"
        aria-label={`Analysis by ${total} engines: ${summary}`}
        className="flex h-2 gap-0.5 overflow-hidden rounded-full"
      >
        {SEGMENTS.filter(({ key }) => detections[key] > 0).map(({ key, fill }) => (
          <span
            key={key}
            className={cn("h-full min-w-[3px] basis-0", fill)}
            style={{ flexGrow: detections[key] }}
          />
        ))}
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-4">
        {SEGMENTS.map(({ key, label, fill }) => (
          <div key={key} className="flex items-center gap-1.5">
            <span aria-hidden className={cn("size-2 shrink-0 rounded-sm", fill)} />
            <dt className="text-muted">{label}</dt>
            <dd className="ml-auto font-medium tabular-nums">{detections[key]}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
