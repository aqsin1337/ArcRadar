import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import Link from "next/link";
import { ConfidenceMeter } from "@/components/ui/confidence-meter";
import {
  IndicatorStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { INDICATOR_TYPE_LABELS, type IndicatorSortField } from "@/lib/indicators/constants";
import type { IndicatorListItem } from "@/lib/indicators/types";
import { indicatorListHref, type ListState } from "@/lib/indicators/url";
import { formatDate, formatDateTime } from "@/lib/format";
import { TagChips } from "./tag-chips";

// Below the container widths in `show`, a column is hidden so the table keeps room for the indicator
// itself. On a narrow container (a phone) the badges move under the value instead, so the verdict,
// severity and origin (the provenance label) are never hidden behind a sideways scroll.
const COLUMNS: { label: string; sort?: IndicatorSortField; show?: string }[] = [
  { label: "Indicator", sort: "value" },
  { label: "Verdict", sort: "verdict", show: "hidden @2xl:table-cell" },
  { label: "Severity", sort: "severity", show: "hidden @2xl:table-cell" },
  { label: "Origin", show: "hidden @2xl:table-cell" },
  { label: "Confidence", sort: "confidence", show: "hidden @3xl:table-cell" },
  { label: "Last seen", sort: "last_seen", show: "hidden @3xl:table-cell" },
  { label: "Status", sort: "status", show: "hidden @5xl:table-cell" },
];

/**
 * The indicator list. Column headers are links that sort (a second click reverses the order), so
 * sorting is a normal navigation: it works without JavaScript and the URL records it.
 */
export function IndicatorTable({ items, state }: { items: IndicatorListItem[]; state: ListState }) {
  const sort = state.sort ?? "last_seen";
  const order = state.order ?? "desc";

  return (
    <div className="@container">
      <Table caption="Indicators">
        <THead>
          <tr>
            {COLUMNS.map(({ label, sort: field, show }) => {
              if (!field)
                return (
                  <Th key={label} className={show}>
                    {label}
                  </Th>
                );
              const current = sort === field;
              const nextOrder = current && order === "asc" ? "desc" : "asc";
              const Icon = !current ? ChevronsUpDown : order === "asc" ? ArrowUp : ArrowDown;
              return (
                <Th
                  key={label}
                  className={show}
                  aria-sort={current ? (order === "asc" ? "ascending" : "descending") : undefined}
                >
                  <Link
                    href={indicatorListHref(state, { sort: field, order: nextOrder, page: 1 })}
                    className="-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-foreground"
                  >
                    {label}
                    <Icon aria-hidden className={current ? "size-3.5" : "size-3.5 opacity-50"} />
                    <span className="sr-only">
                      , sort {nextOrder === "asc" ? "ascending" : "descending"}
                    </span>
                  </Link>
                </Th>
              );
            })}
          </tr>
        </THead>
        <TBody>
          {items.map((item) => (
            <Tr key={item.id}>
              <Td className="min-w-48 max-w-md">
                <p className="text-xs text-muted">{INDICATOR_TYPE_LABELS[item.type]}</p>
                <Link
                  href={`/indicators/${item.id}`}
                  className="font-mono text-sm font-medium [overflow-wrap:anywhere] text-primary hover:underline"
                >
                  {item.value}
                </Link>
                <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
                  <VerdictBadge verdict={item.verdict} />
                  <SeverityBadge severity={item.severity} />
                  <OriginBadge origin={item.origin} />
                  <IndicatorStatusBadge status={item.status} />
                </div>
                {item.tags.length > 0 && (
                  <div className="mt-1.5">
                    <TagChips tags={item.tags} limit={3} />
                  </div>
                )}
              </Td>
              <Td className="hidden @2xl:table-cell">
                <VerdictBadge verdict={item.verdict} />
              </Td>
              <Td className="hidden @2xl:table-cell">
                <SeverityBadge severity={item.severity} />
              </Td>
              <Td className="hidden @2xl:table-cell">
                <OriginBadge origin={item.origin} />
              </Td>
              <Td className="hidden @3xl:table-cell">
                <ConfidenceMeter value={item.confidence} />
              </Td>
              <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
                <time dateTime={item.last_seen} title={formatDateTime(item.last_seen)}>
                  {formatDate(item.last_seen)}
                </time>
              </Td>
              <Td className="hidden @5xl:table-cell">
                <IndicatorStatusBadge status={item.status} />
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
