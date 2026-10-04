import Link from "next/link";
import { AlertStatusBadge, OriginBadge, SeverityBadge } from "@/components/ui/domain-badges";
import { SortHeader } from "@/components/ui/sort-header";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import type { AlertSortField } from "@/lib/alerts/constants";
import type { AlertListItem } from "@/lib/alerts/types";
import { alertListHref } from "@/lib/alerts/url";
import { formatDate, formatDateTime, personLabel } from "@/lib/format";
import type { ListState } from "@/lib/validation/list-url";

// Below the container widths in `show`, a column is hidden so the table keeps room for the title. On a
// narrow container (a phone) the badges, including the provenance label, move under the title.
const COLUMNS: { label: string; sort?: AlertSortField; show?: string }[] = [
  { label: "Alert" },
  { label: "Severity", sort: "severity", show: "hidden @2xl:table-cell" },
  { label: "Status", sort: "status", show: "hidden @2xl:table-cell" },
  { label: "Assigned to", show: "hidden @3xl:table-cell" },
  { label: "Origin", show: "hidden @3xl:table-cell" },
  { label: "Created", sort: "created_at", show: "hidden @3xl:table-cell" },
];

/** The alert list. Column headers are links that sort, as in the other lists. */
export function AlertTable({ items, state }: { items: AlertListItem[]; state: ListState }) {
  const sort = String(state.sort ?? "created_at");
  const order = String(state.order ?? "desc");

  return (
    <div className="@container">
      <Table caption="Alerts">
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
                    alertListHref(state, { sort: sortField, order: nextOrder, page: 1 })
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
                  href={`/alerts/${item.id}`}
                  className="text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline"
                >
                  {item.title}
                </Link>
                <p className="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">
                  {item.source}
                  {item.asset && ` · ${item.asset.name}`}
                  {item.indicator && (
                    <>
                      {" · "}
                      <span className="font-mono">{item.indicator.value}</span>
                    </>
                  )}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
                  <SeverityBadge severity={item.severity} />
                  <AlertStatusBadge status={item.status} />
                  <OriginBadge origin={item.origin} />
                </div>
                <p className="mt-1.5 text-xs text-muted @3xl:hidden">
                  {item.assignee ? personLabel(item.assignee) : "Unassigned"}
                </p>
              </Td>
              <Td className="hidden @2xl:table-cell">
                <SeverityBadge severity={item.severity} />
              </Td>
              <Td className="hidden @2xl:table-cell">
                <AlertStatusBadge status={item.status} />
              </Td>
              <Td className="hidden text-sm @3xl:table-cell">
                {item.assignee ? (
                  personLabel(item.assignee)
                ) : (
                  <span className="text-muted">Unassigned</span>
                )}
              </Td>
              <Td className="hidden @3xl:table-cell">
                <OriginBadge origin={item.origin} />
              </Td>
              <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
                <time dateTime={item.created_at} title={formatDateTime(item.created_at)}>
                  {formatDate(item.created_at)}
                </time>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
