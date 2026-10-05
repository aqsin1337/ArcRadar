import Link from "next/link";
import { OriginBadge, SeverityBadge } from "@/components/ui/domain-badges";
import { SortHeader } from "@/components/ui/sort-header";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";
import type { EventListItem } from "@/lib/telemetry/types";
import { eventList } from "@/lib/telemetry/url";
import type { ListState } from "@/lib/validation/list-url";

// Below the container widths in `show`, a column is hidden so the table keeps room for the title. On a
// narrow container (a phone) the badges, including the provenance label, move under the title.
const COLUMNS: { label: string; sort?: string; show?: string }[] = [
  { label: "Event" },
  { label: "Severity", sort: "severity", show: "hidden @2xl:table-cell" },
  { label: "Source", show: "hidden @3xl:table-cell" },
  { label: "Origin", show: "hidden @3xl:table-cell" },
  { label: "Happened", sort: "occurred_at", show: "hidden @3xl:table-cell" },
];

/** The events list. An event that raised an alert links to it; column headers sort. */
export function EventTable({ items, state }: { items: EventListItem[]; state: ListState }) {
  const sort = String(state.sort ?? "occurred_at");
  const order = String(state.order ?? "desc");

  return (
    <div className="@container">
      <Table caption="Events">
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
                    `${eventList.href(state, { sort: sortField, order: nextOrder, page: 1 })}#events`
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
                {item.alert_id ? (
                  <Link
                    href={`/alerts/${item.alert_id}`}
                    className="text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline"
                  >
                    {item.title}
                  </Link>
                ) : (
                  <span className="text-sm font-medium [overflow-wrap:anywhere]">{item.title}</span>
                )}
                <p className="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">
                  {item.event_type}
                  {item.asset && ` · ${item.asset.name}`}
                  {item.alert_id && " · raised an alert"}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
                  <SeverityBadge severity={item.severity} />
                  <OriginBadge origin={item.origin} />
                </div>
                <p className="mt-1.5 text-xs text-muted @3xl:hidden">
                  <time dateTime={item.occurred_at} title={item.occurred_at}>
                    {formatDateTime(item.occurred_at)}
                  </time>
                </p>
              </Td>
              <Td className="hidden @2xl:table-cell">
                <SeverityBadge severity={item.severity} />
              </Td>
              <Td className="hidden text-sm @3xl:table-cell">{item.source}</Td>
              <Td className="hidden @3xl:table-cell">
                <OriginBadge origin={item.origin} />
              </Td>
              <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
                <time dateTime={item.occurred_at} title={item.occurred_at}>
                  {formatDateTime(item.occurred_at)}
                </time>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
