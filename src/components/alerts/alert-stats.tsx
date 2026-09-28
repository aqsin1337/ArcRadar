import Link from "next/link";
import type { ReactNode } from "react";
import { AlertStatusBadge } from "@/components/ui/domain-badges";
import { cn } from "@/lib/cn";
import { ASSIGNEE_NONE } from "@/lib/alerts/constants";
import type { AlertStats } from "@/lib/alerts/types";
import { alertListHref } from "@/lib/alerts/url";
import type { ListState } from "@/lib/validation/list-url";

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
 * Alert counts as stat tiles: all, unassigned, and one per status in lifecycle order. Each tile is a
 * link that filters the list to it, and the tile of the active filter is marked.
 */
export function AlertStatsTiles({ stats, state }: { stats: AlertStats; state: ListState }) {
  const filter = (overrides: ListState) =>
    alertListHref({ ...state, status: "", assignee: "" }, { ...overrides, page: 1 });

  return (
    <section aria-label="Alert statistics">
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        <li className="contents">
          <Tile
            href={filter({})}
            current={!state.status && !state.assignee}
            label="All alerts"
            count={stats.total}
          />
        </li>
        <li className="contents">
          <Tile
            href={filter({ assignee: ASSIGNEE_NONE })}
            current={state.assignee === ASSIGNEE_NONE && !state.status}
            label="Unassigned"
            count={stats.unassigned}
          />
        </li>
        {stats.by_status.map((row) => (
          <li key={row.status} className="contents">
            <Tile
              href={filter({ status: row.status })}
              current={state.status === row.status && !state.assignee}
              label={<AlertStatusBadge status={row.status} />}
              count={row.total}
              note={row.unassigned > 0 ? `${row.unassigned} unassigned` : undefined}
            />
          </li>
        ))}
      </ul>
    </section>
  );
}
