import type { Tone } from "./badge";

// Full class names on purpose: Tailwind only generates classes it can find as literal strings.
const BAR_FILL: Record<Tone, string> = {
  slate: "bg-tone-slate-fg",
  brand: "bg-tone-brand-fg",
  blue: "bg-tone-blue-fg",
  green: "bg-tone-green-fg",
  amber: "bg-tone-amber-fg",
  orange: "bg-tone-orange-fg",
  red: "bg-tone-red-fg",
  violet: "bg-tone-violet-fg",
};

export type DistributionRow = { label: string; total: number; tone?: Tone };

/**
 * A magnitude-by-category chart: one bar per row, sized relative to the largest value. Give a `tone`
 * per row when the categories already carry a color elsewhere (severity, verdict); leave it out for
 * a single accent color when the bars are not otherwise color-coded (an IOC type, say).
 */
export function DistributionBars({ rows }: { rows: DistributionRow[] }) {
  const max = Math.max(1, ...rows.map((row) => row.total));
  if (rows.every((row) => row.total === 0)) {
    return <p className="text-sm text-muted">No data yet.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {rows.map((row) => (
        <li key={row.label} className="flex items-center gap-3 text-sm">
          <span className="w-32 shrink-0 truncate sm:w-40" title={row.label}>
            {row.label}
          </span>
          <span className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
            <span
              className={`block h-full rounded-full ${row.tone ? BAR_FILL[row.tone] : "bg-primary"}`}
              style={{ width: `${(row.total / max) * 100}%` }}
            />
          </span>
          <span className="w-8 shrink-0 text-right tabular-nums text-muted">{row.total}</span>
        </li>
      ))}
    </ul>
  );
}
