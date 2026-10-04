import Link from "next/link";
import { TagChips } from "@/components/indicators/tag-chips";
import {
  InvestigationStatusBadge,
  OriginBadge,
  PriorityBadge,
} from "@/components/ui/domain-badges";
import { SortHeader } from "@/components/ui/sort-header";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { formatDate, formatDateTime, personLabel } from "@/lib/format";
import type { InvestigationSortField } from "@/lib/investigations/constants";
import type { InvestigationListItem } from "@/lib/investigations/types";
import { investigationListHref } from "@/lib/investigations/url";
import type { ListState } from "@/lib/validation/list-url";

// Below the container widths in `show`, a column is hidden so the table keeps room for the title. On a
// narrow container (a phone) the badges, including the provenance label, move under the title.
const COLUMNS: { label: string; sort?: InvestigationSortField; show?: string }[] = [
  { label: "Investigation", sort: "title" },
  { label: "Status", sort: "status", show: "hidden @2xl:table-cell" },
  { label: "Priority", sort: "priority", show: "hidden @2xl:table-cell" },
  { label: "Analyst", show: "hidden @3xl:table-cell" },
  { label: "Attached", show: "hidden @3xl:table-cell" },
  { label: "Origin", show: "hidden @3xl:table-cell" },
  { label: "Updated", sort: "updated_at", show: "hidden @3xl:table-cell" },
];

/** The investigation list. Column headers are links that sort, as in the other lists. */
export function InvestigationTable({
  items,
  state,
}: {
  items: InvestigationListItem[];
  state: ListState;
}) {
  const sort = String(state.sort ?? "updated_at");
  const order = String(state.order ?? "desc");

  return (
    <div className="@container">
      <Table caption="Investigations">
        <THead>
          <tr>
            {COLUMNS.map(({ label, sort: field, show }) =>
              field ? (
                <SortHeader
                  key={label}
                  label={label}
                  field={field}
                  sort={sort}
                  order={order}
                  className={show}
                  hrefFor={(sortField, nextOrder) =>
                    investigationListHref(state, { sort: sortField, order: nextOrder, page: 1 })
                  }
                />
              ) : (
                <Th key={label} className={show}>
                  {label}
                </Th>
              ),
            )}
          </tr>
        </THead>
        <TBody>
          {items.map((item) => (
            <Tr key={item.id}>
              <Td className="max-w-lg min-w-48">
                <Link
                  href={`/investigations/${item.id}`}
                  className="text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline"
                >
                  {item.title}
                </Link>
                <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
                  <InvestigationStatusBadge status={item.status} />
                  <PriorityBadge priority={item.priority} />
                  <OriginBadge origin={item.origin} />
                </div>
                {item.tags.length > 0 && (
                  <div className="mt-1.5">
                    <TagChips tags={item.tags} limit={3} />
                  </div>
                )}
                <p className="mt-1.5 text-xs text-muted @3xl:hidden">
                  {item.analyst ? personLabel(item.analyst) : "Unassigned"} · {item.indicator_count}{" "}
                  indicators · {item.alert_count} alerts
                </p>
              </Td>
              <Td className="hidden @2xl:table-cell">
                <InvestigationStatusBadge status={item.status} />
              </Td>
              <Td className="hidden @2xl:table-cell">
                <PriorityBadge priority={item.priority} />
              </Td>
              <Td className="hidden text-sm @3xl:table-cell">
                {item.analyst ? (
                  personLabel(item.analyst)
                ) : (
                  <span className="text-muted">Unassigned</span>
                )}
              </Td>
              <Td className="hidden text-sm whitespace-nowrap text-muted tabular-nums @3xl:table-cell">
                {item.indicator_count} indicators, {item.alert_count} alerts
              </Td>
              <Td className="hidden @3xl:table-cell">
                <OriginBadge origin={item.origin} />
              </Td>
              <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
                <time dateTime={item.updated_at} title={formatDateTime(item.updated_at)}>
                  {formatDate(item.updated_at)}
                </time>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
