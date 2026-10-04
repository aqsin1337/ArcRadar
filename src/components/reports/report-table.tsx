import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { TimeText } from "@/components/ui/detail-list";
import { OriginBadge } from "@/components/ui/domain-badges";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { REPORT_TYPE_LABELS } from "@/lib/reports/constants";
import type { ReportListItem } from "@/lib/reports/types";

export function ReportTable({ items }: { items: ReportListItem[] }) {
  return (
    <Table caption="Reports">
      <THead>
        <Tr>
          <Th>Title</Th>
          <Th className="hidden @lg:table-cell">Type</Th>
          <Th className="hidden @lg:table-cell">Origin</Th>
          <Th className="hidden @xl:table-cell">Created by</Th>
          <Th>Generated</Th>
        </Tr>
      </THead>
      <TBody>
        {items.map((report) => (
          <Tr key={report.id}>
            <Td>
              <Link
                href={`/reports/${report.id}`}
                className="font-medium text-primary hover:underline"
              >
                {report.title}
              </Link>
              <span className="mt-1 flex flex-wrap items-center gap-1.5 @lg:hidden">
                <Badge tone="slate">{REPORT_TYPE_LABELS[report.type]}</Badge>
                <OriginBadge origin={report.origin} />
              </span>
            </Td>
            <Td className="hidden @lg:table-cell">
              <Badge tone="slate">{REPORT_TYPE_LABELS[report.type]}</Badge>
            </Td>
            <Td className="hidden @lg:table-cell">
              <OriginBadge origin={report.origin} />
            </Td>
            <Td className="hidden @xl:table-cell text-sm text-muted">
              {report.created_by_name ?? "—"}
            </Td>
            <Td className="text-sm text-muted">
              <TimeText iso={report.created_at} />
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  );
}
