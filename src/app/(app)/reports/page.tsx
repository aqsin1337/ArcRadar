import { FileText, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ReportFilters } from "@/components/reports/report-filters";
import { ReportTable } from "@/components/reports/report-table";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseReportListParams } from "@/lib/reports/schema";
import { listReports } from "@/lib/reports/service";
import { reportList } from "@/lib/reports/url";

export const metadata: Metadata = { title: "Reports" };

export default async function ReportsPage({ searchParams }: PageProps<"/reports">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("reports:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseReportListParams(await searchParams);
  const { items, pagination } = await listReports(auth, query);
  const filtered = reportList.hasActive(query);
  const canWrite = auth.permissions.has("reports:write");

  return (
    <>
      <PageHeader
        title="Reports"
        description="Generated summaries of the workspace's data: a snapshot at the moment they were made, not a live view."
        actions={
          canWrite && (
            <Link href="/reports/new" className={buttonClasses()}>
              <Plus aria-hidden className="size-4" />
              New report
            </Link>
          )
        }
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}
        <ReportFilters state={query} />
        <ListResults
          pagination={pagination}
          count={items.length}
          filtered={filtered}
          noun={["report", "reports"]}
          listHref="/reports"
          hrefForPage={(page) => reportList.href(query, { page })}
          empty={{
            icon: FileText,
            title: filtered ? "No reports match" : "No reports yet",
            description: filtered
              ? "Try fewer words or a different type."
              : canWrite
                ? "Generate one from the current alerts, indicators, vulnerabilities, an investigation or a threat actor."
                : "An analyst or administrator can generate one.",
            action: canWrite && !filtered && (
              <Link href="/reports/new" className={buttonClasses()}>
                New report
              </Link>
            ),
          }}
        >
          <ReportTable items={items} />
        </ListResults>
      </div>
    </>
  );
}
