import Link from "next/link";
import { InvestigationStatusBadge } from "@/components/ui/domain-badges";
import { cn } from "@/lib/cn";
import type { InvestigationStats } from "@/lib/investigations/types";
import { investigationListHref } from "@/lib/investigations/url";
import type { ListState } from "@/lib/validation/list-url";

/**
 * Investigation counts as stat tiles: all, and one per status in lifecycle order. Each tile is a link
 * that filters the list to it, and the tile of the active filter is marked.
 */
export function InvestigationStatsTiles({
  stats,
  state,
}: {
  stats: InvestigationStats;
  state: ListState;
}) {
  const href = (status: string) =>
    investigationListHref({ ...state, status: "" }, { status, page: 1 });
  const tile = (current: boolean) =>
    cn(
      "flex min-w-0 flex-col justify-between gap-2 rounded-xl border bg-surface p-3 transition-colors hover:bg-surface-2",
      current ? "border-primary" : "border-border",
    );

  return (
    <section aria-label="Investigation statistics">
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <li className="contents">
          <Link
            href={href("")}
            aria-current={!state.status ? "true" : undefined}
            className={tile(!state.status)}
          >
            <span className="text-sm text-muted">All investigations</span>
            <span className="block text-2xl font-semibold tracking-tight tabular-nums">
              {stats.total}
            </span>
          </Link>
        </li>
        {stats.by_status.map((row) => (
          <li key={row.status} className="contents">
            <Link
              href={href(row.status)}
              aria-current={state.status === row.status ? "true" : undefined}
              className={tile(state.status === row.status)}
            >
              <span className="text-sm text-muted">
                <InvestigationStatusBadge status={row.status} />
              </span>
              <span className="block text-2xl font-semibold tracking-tight tabular-nums">
                {row.total}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
