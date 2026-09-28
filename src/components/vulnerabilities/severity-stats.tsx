import Link from "next/link";
import type { ReactNode } from "react";
import { SeverityBadge } from "@/components/ui/domain-badges";
import { cn } from "@/lib/cn";
import type { VulnerabilityStats } from "@/lib/vulnerabilities/types";
import { vulnerabilityListHref, type VulnerabilityListState } from "@/lib/vulnerabilities/url";

function Tile({
  href,
  current,
  label,
  count,
  note,
}: {
  href: string;
  current: boolean;
  label: ReactNode;
  count: number;
  note?: string;
}) {
  return (
    <Link
      href={href}
      aria-current={current ? "true" : undefined}
      className={cn(
        "flex min-w-0 flex-col justify-between gap-2 rounded-xl border bg-surface p-3 transition-colors hover:bg-surface-2",
        current ? "border-primary" : "border-border",
      )}
    >
      <span className="text-sm text-muted">{label}</span>
      <span>
        <span className="block text-2xl font-semibold tracking-tight tabular-nums">{count}</span>
        {note && <span className="block text-xs text-muted">{note}</span>}
      </span>
    </Link>
  );
}

/**
 * Record counts as stat tiles, one per severity, most severe first. Each tile is a link that filters
 * the list to it (and the tile of the active filter is marked), so the numbers are also the navigation.
 */
export function SeverityStats({
  stats,
  state,
}: {
  stats: VulnerabilityStats;
  state: VulnerabilityListState;
}) {
  const filter = (overrides: VulnerabilityListState) =>
    vulnerabilityListHref(
      { ...state, severity: "", exploit_status: "" },
      { ...overrides, page: 1 },
    );

  return (
    <section aria-label="Vulnerability statistics">
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        <li className="contents">
          <Tile
            href={filter({})}
            current={!state.severity && !state.exploit_status}
            label="All vulnerabilities"
            count={stats.total}
          />
        </li>
        <li className="contents">
          <Tile
            href={filter({ exploit_status: "exploited_in_wild" })}
            current={state.exploit_status === "exploited_in_wild"}
            label="Exploited in the wild"
            count={stats.exploited}
          />
        </li>
        {stats.by_severity.map((row) => (
          <li key={row.severity} className="contents">
            <Tile
              href={filter({ severity: row.severity })}
              current={state.severity === row.severity}
              label={<SeverityBadge severity={row.severity} />}
              count={row.total}
              note={row.exploited > 0 ? `${row.exploited} exploited` : undefined}
            />
          </li>
        ))}
      </ul>
    </section>
  );
}
