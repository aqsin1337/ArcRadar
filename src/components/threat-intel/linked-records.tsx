import Link from "next/link";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { OriginBadge, SeverityBadge, VerdictBadge } from "@/components/ui/domain-badges";
import { INDICATOR_TYPE_SHORT_LABELS } from "@/lib/indicators/constants";
import type { LinkedIndicators } from "@/lib/threat-intel/types";
import type { DataOrigin } from "@/types/domain";

export type RecordChip = {
  id: string;
  label: string;
  href: string;
  origin?: DataOrigin;
  /** Small text after the label, for example a campaign's status. */
  detail?: ReactNode;
};

/** Records linked to this one, as links that carry their provenance label. */
export function RecordChips({ items, empty }: { items: RecordChip[]; empty: string }) {
  if (items.length === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <ul className="flex flex-wrap gap-2">
      {items.map((item) => (
        <li
          key={item.id}
          className="inline-flex max-w-full flex-wrap items-center gap-1.5 rounded-lg border border-border bg-surface-2/50 px-2.5 py-1.5 text-sm"
        >
          <Link
            href={item.href}
            className="font-medium text-primary [overflow-wrap:anywhere] hover:underline"
          >
            {item.label}
          </Link>
          {item.detail && <span className="text-xs text-muted">{item.detail}</span>}
          {item.origin && <OriginBadge origin={item.origin} />}
        </li>
      ))}
    </ul>
  );
}

/** The first indicators linked to a record (each with type, verdict, severity and provenance) and the total. */
export function LinkedIndicatorList({ indicators }: { indicators: LinkedIndicators }) {
  if (indicators.total === 0) {
    return <p className="text-sm text-muted">No indicators are linked to this record.</p>;
  }
  return (
    <div className="space-y-3">
      <ul className="divide-y divide-border">
        {indicators.items.map((indicator) => (
          <li
            key={indicator.id}
            className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5 text-sm"
          >
            <Link
              href={`/indicators/${indicator.id}`}
              className="min-w-0 font-mono font-medium break-all text-primary hover:underline"
            >
              {indicator.value}
              <span className="sr-only"> ({INDICATOR_TYPE_SHORT_LABELS[indicator.type]})</span>
            </Link>
            <span className="ml-auto flex flex-wrap items-center gap-1.5">
              <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[indicator.type]}</Badge>
              <VerdictBadge verdict={indicator.verdict} />
              <SeverityBadge severity={indicator.severity} />
              <OriginBadge origin={indicator.origin} />
            </span>
          </li>
        ))}
      </ul>
      {indicators.total > indicators.items.length && (
        <p className="text-xs text-muted">
          Showing {indicators.items.length} of {indicators.total} indicators, in alphabetical order.
        </p>
      )}
    </div>
  );
}

/** A chip list of short text values (aliases, industries, countries, platforms). */
export function ValueChips({ values, empty }: { values: string[]; empty: string }) {
  if (values.length === 0) return <span className="text-muted">{empty}</span>;
  return (
    <span className="inline-flex flex-wrap justify-end gap-1.5">
      {values.map((value) => (
        <Badge key={value} tone="slate">
          {value}
        </Badge>
      ))}
    </span>
  );
}
