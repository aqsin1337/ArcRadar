import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { NewReportForm } from "@/components/reports/new-report-form";
import { getPageAuthContext } from "@/lib/auth/session";

export const metadata: Metadata = { title: "New report" };

export default async function NewReportPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("reports:write")) return <AccessDenied />;

  return (
    <>
      <PageHeader
        title="New report"
        description="Generates a snapshot from the workspace's current data. A report never changes after it is made; generate a new one to refresh it."
      />
      <NewReportForm />
    </>
  );
}
