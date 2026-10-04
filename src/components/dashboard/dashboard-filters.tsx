import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { SEVERITIES, SEVERITY_LABELS } from "@/lib/indicators/constants";
import type { DashboardQuery } from "@/lib/dashboard/schema";

const DAY_OPTIONS = [7, 14, 30, 90];

/** Two plain GET forms: one narrows the charts and recent panels, the other jumps into indicator
 * search. No client JavaScript is needed for either. */
export function DashboardFilters({ query }: { query: DashboardQuery }) {
  return (
    <div className="flex flex-wrap items-end gap-3">
      <form method="get" className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-sm">
          <span className="text-muted">Window</span>
          <Select name="days" defaultValue={String(query.days)} className="h-9 w-32">
            {DAY_OPTIONS.map((days) => (
              <option key={days} value={days}>
                Last {days} days
              </option>
            ))}
          </Select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted">Severity</span>
          <Select name="severity" defaultValue={query.severity ?? ""} className="h-9 w-36">
            <option value="">Any severity</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABELS[severity]}
              </option>
            ))}
          </Select>
        </label>
        <button
          type="submit"
          className="h-9 rounded-lg border border-input-border px-3 text-sm hover:bg-surface-2"
        >
          Apply
        </button>
        {(query.days !== 14 || query.severity) && (
          <a href="/dashboard" className="text-sm text-muted underline underline-offset-2">
            Reset
          </a>
        )}
      </form>

      <form action="/indicators" method="get" role="search" className="flex items-end gap-2">
        <label className="space-y-1 text-sm">
          <span className="text-muted">Search records</span>
          <span className="relative block">
            <Search
              aria-hidden
              className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted"
            />
            <Input name="q" placeholder="Search indicators…" className="h-9 w-48 pl-8" />
          </span>
        </label>
        <button
          type="submit"
          className="h-9 rounded-lg border border-input-border px-3 text-sm hover:bg-surface-2"
        >
          Search
        </button>
      </form>
    </div>
  );
}
