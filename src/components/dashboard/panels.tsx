import Link from "next/link";
import type { ReactNode } from "react";
import {
  AlertStatusBadge,
  InvestigationStatusBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { INDICATOR_TYPE_SHORT_LABELS } from "@/lib/indicators/constants";
import type { AlertListItem } from "@/lib/alerts/types";
import type { IndicatorListItem } from "@/lib/indicators/types";
import type { InvestigationListItem } from "@/lib/investigations/types";
import { alertListHref } from "@/lib/alerts/url";
import type { TopTechnique } from "@/lib/mitre/service";

function Panel({
  title,
  viewAllHref,
  children,
}: {
  title: string;
  viewAllHref: string;
  children: ReactNode;
}) {
  return (
    <section className="space-y-2 rounded-xl border border-border bg-surface p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">{title}</h2>
        <Link href={viewAllHref} className="text-xs text-primary hover:underline">
          View all
        </Link>
      </div>
      {children}
    </section>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="py-2 text-sm text-muted">{text}</p>;
}

export function IndicatorPanel({
  title,
  viewAllHref,
  items,
  emptyText,
}: {
  title: string;
  viewAllHref: string;
  items: IndicatorListItem[];
  emptyText: string;
}) {
  return (
    <Panel title={title} viewAllHref={viewAllHref}>
      {items.length === 0 ? (
        <Empty text={emptyText} />
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
              <Link
                href={`/indicators/${item.id}`}
                className="min-w-0 truncate font-mono text-[13px] text-primary hover:underline"
              >
                {item.value}
              </Link>
              <span className="flex shrink-0 items-center gap-1.5 text-xs text-muted">
                {INDICATOR_TYPE_SHORT_LABELS[item.type]}
                <VerdictBadge verdict={item.verdict} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function AlertPanel({ items }: { items: AlertListItem[] }) {
  return (
    <Panel title="Recent alerts" viewAllHref="/alerts">
      {items.length === 0 ? (
        <Empty text="No alerts yet." />
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
              <Link
                href={`/alerts/${item.id}`}
                className="min-w-0 truncate text-primary hover:underline"
              >
                {item.title}
              </Link>
              <AlertStatusBadge status={item.status} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function InvestigationPanel({ items }: { items: InvestigationListItem[] }) {
  return (
    <Panel title="Recent investigations" viewAllHref="/investigations">
      {items.length === 0 ? (
        <Empty text="No investigations yet." />
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
              <Link
                href={`/investigations/${item.id}`}
                className="min-w-0 truncate text-primary hover:underline"
              >
                {item.title}
              </Link>
              <InvestigationStatusBadge status={item.status} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function TopTechniquesPanel({ items }: { items: TopTechnique[] }) {
  return (
    <Panel title="Most seen ATT&CK techniques" viewAllHref="/mitre">
      {items.length === 0 ? (
        <Empty text="No alert has named a technique yet." />
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-2 py-1.5 text-sm">
              <Link
                href={alertListHref({}, { technique: item.id })}
                className="min-w-0 truncate text-primary hover:underline"
              >
                <span className="font-mono">{item.id}</span> {item.name}
              </Link>
              <span className="shrink-0 text-xs tabular-nums text-muted">
                {item.alert_count} alert{item.alert_count === 1 ? "" : "s"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
