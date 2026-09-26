import type { Metadata } from "next";
import Link from "next/link";
import { IndicatorForm } from "@/components/indicators/indicator-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { listTagOptions } from "@/lib/indicators/service";

export const metadata: Metadata = { title: "New indicator" };

export default async function NewIndicatorPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("indicators:write")) {
    return (
      <AccessDenied
        title="You can't add indicators"
        description="Adding indicators needs the analyst or administrator role. You can still browse and search them."
        action={
          <Link href="/indicators" className={buttonClasses({ variant: "secondary" })}>
            Back to indicators
          </Link>
        }
      />
    );
  }

  const tags = await listTagOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title="New indicator"
        description="Record an observable you want to track. It is saved as local data and is checked for duplicates."
      />
      <Card className="max-w-3xl">
        <CardContent>
          <IndicatorForm mode="create" tagOptions={tags.map((tag) => tag.name)} />
        </CardContent>
      </Card>
    </>
  );
}
