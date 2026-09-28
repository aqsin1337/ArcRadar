import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DeleteRecordButton } from "@/components/ui/delete-record-button";
import { OriginBadge } from "@/components/ui/domain-badges";
import { TimeText } from "@/components/ui/detail-list";
import { AccessDenied } from "@/components/ui/states";
import { PrintButton } from "@/components/reports/print-button";
import { ReportContent } from "@/components/reports/report-content";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { REPORT_TYPE_LABELS } from "@/lib/reports/constants";
import { getReport, isReportId } from "@/lib/reports/service";
import type { ReportDetail } from "@/lib/reports/types";

export default async function ReportPage({ params }: PageProps<"/reports/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("reports:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isReportId(id)) notFound();

  let report: ReportDetail | null = null;
  try {
    report = await getReport(auth, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!report) notFound();

  const canWrite = auth.permissions.has("reports:write");

  return (
    <>
      <title>{`${report.title} · Reports · ArcRadar`}</title>

      <Link
        href="/reports"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground print:hidden"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All reports
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="report-title">
            {report.title}
          </h1>
          <p
            className="flex flex-wrap items-center gap-2 text-sm text-muted"
            data-testid="report-subtitle"
          >
            {REPORT_TYPE_LABELS[report.type]} · Generated <TimeText iso={report.created_at} /> by{" "}
            {report.created_by_name ?? "someone no longer in the workspace"}
            <OriginBadge origin={report.origin} />
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2 print:hidden">
          <PrintButton />
          {canWrite && (
            <DeleteRecordButton
              endpoint={`/api/reports/${report.id}`}
              listHref="/reports"
              noun="report"
              name={report.title}
              consequence="It is only a generated snapshot; nothing else is affected."
            />
          )}
        </div>
      </div>

      <ReportContent type={report.type} content={report.content as object} />
    </>
  );
}
