import Link from "next/link";
import { OriginBadge } from "@/components/ui/domain-badges";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { formatDateTime } from "@/lib/format";
import type { AssetListItem } from "@/lib/telemetry/types";

/**
 * The machines telemetry comes from, most recently seen first. The name links to the alerts that
 * mention it (alert search covers an asset's name and address).
 */
export function AssetTable({ items }: { items: AssetListItem[] }) {
  return (
    <div className="@container">
      <Table caption="Assets">
        <THead>
          <tr>
            <Th>Asset</Th>
            <Th className="hidden @2xl:table-cell">Address</Th>
            <Th className="hidden @2xl:table-cell">System</Th>
            <Th className="hidden @3xl:table-cell">Source</Th>
            <Th className="hidden @3xl:table-cell">Origin</Th>
            <Th className="hidden @3xl:table-cell">Last seen</Th>
          </tr>
        </THead>
        <TBody>
          {items.map((item) => (
            <Tr key={item.id}>
              <Td className="max-w-lg min-w-40">
                <Link
                  href={`/alerts?q=${encodeURIComponent(item.name)}`}
                  className="text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline"
                >
                  {item.name}
                  <span className="sr-only">: alerts on this asset</span>
                </Link>
                <p className="mt-0.5 text-xs text-muted [overflow-wrap:anywhere] @2xl:hidden">
                  {[item.ip_address, item.os].filter(Boolean).join(" · ") || "No address recorded"}
                </p>
                <div className="mt-2 @3xl:hidden">
                  <OriginBadge origin={item.origin} />
                </div>
              </Td>
              <Td className="hidden font-mono text-[13px] @2xl:table-cell">
                {item.ip_address ?? <span className="font-sans text-muted">—</span>}
              </Td>
              <Td className="hidden text-sm @2xl:table-cell">
                {item.os ?? <span className="text-muted">Unknown</span>}
              </Td>
              <Td className="hidden text-sm @3xl:table-cell">{item.source}</Td>
              <Td className="hidden @3xl:table-cell">
                <OriginBadge origin={item.origin} />
              </Td>
              <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
                <time dateTime={item.last_seen} title={item.last_seen}>
                  {formatDateTime(item.last_seen)}
                </time>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
