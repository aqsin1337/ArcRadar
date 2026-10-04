import type { Metadata } from "next";
import Link from "next/link";
import { InvestigationForm } from "@/components/investigations/investigation-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { listTagOptions } from "@/lib/indicators/service";
import { findTeamMembers } from "@/lib/team/repository";

export const metadata: Metadata = { title: "New investigation" };

export default async function NewInvestigationPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("investigations:write")) {
    return (
      <AccessDenied
        title="You can't open investigations"
        description="Opening investigations needs the analyst or administrator role. You can still browse and search them."
        action={
          <Link href="/investigations" className={buttonClasses({ variant: "secondary" })}>
            Back to investigations
          </Link>
        }
      />
    );
  }

  const [people, tags] = await Promise.all([
    findTeamMembers(auth.supabase, "investigations:write"),
    listTagOptions(auth.supabase),
  ]);
  return (
    <>
      <PageHeader
        title="New investigation"
        description="Open a case. It starts as Open and is saved as local data; attach indicators and alerts on the next page."
      />
      <Card className="max-w-2xl">
        <CardContent>
          <InvestigationForm people={people} tagOptions={tags.map((tag) => tag.name)} />
        </CardContent>
      </Card>
    </>
  );
}
