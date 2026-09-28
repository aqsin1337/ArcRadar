import type { Metadata } from "next";
import Link from "next/link";
import { AlertForm } from "@/components/alerts/alert-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";

export const metadata: Metadata = { title: "New alert" };

export default async function NewAlertPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("alerts:write")) {
    return (
      <AccessDenied
        title="You can't create alerts"
        description="Creating alerts needs the analyst or administrator role. You can still browse and search them."
        action={
          <Link href="/alerts" className={buttonClasses({ variant: "secondary" })}>
            Back to alerts
          </Link>
        }
      />
    );
  }

  return (
    <>
      <PageHeader
        title="New alert"
        description="Record something that needs attention. It is saved as a manual, local alert and starts as New."
      />
      <Card className="max-w-2xl">
        <CardContent>
          <AlertForm />
        </CardContent>
      </Card>
    </>
  );
}
