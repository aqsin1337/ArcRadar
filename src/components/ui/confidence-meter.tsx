import { cn } from "@/lib/cn";

/** Confidence as a number with a thin bar. The number carries the meaning; the bar is decoration. */
export function ConfidenceMeter({ value, className }: { value: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 text-sm tabular-nums", className)}>
      <span aria-hidden className="h-1.5 w-10 overflow-hidden rounded-full bg-surface-2">
        <span className="block h-full rounded-full bg-primary" style={{ width: `${value}%` }} />
      </span>
      <span>
        {value}
        <span className="text-muted">%</span>
      </span>
    </span>
  );
}
