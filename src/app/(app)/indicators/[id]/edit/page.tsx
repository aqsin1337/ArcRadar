import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { IndicatorForm } from "@/components/indicators/indicator-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getIndicator, isIndicatorId, listTagOptions } from "@/lib/indicators/service";
import type { IndicatorDetail } from "@/lib/indicators/types";

export const metadata: Metadata = { title: "Edit indicator" };

export default async function EditIndicatorPage({ params }: PageProps<"/indicators/[id]/edit">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const { id } = await params;
  if (!isIndicatorId(id)) notFound();

  if (!auth.permissions.has("indicators:write")) {
    return (
      <AccessDenied
        title="You can't edit indicators"
        description="Editing needs the analyst or administrator role."
        action={
          <Link href={`/indicators/${id}`} className={buttonClasses({ variant: "secondary" })}>
            Back to the indicator
          </Link>
        }
      />
    );
  }

  let indicator: IndicatorDetail | null = null;
  try {
    indicator = await getIndicator(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!indicator) notFound();

  const tags = await listTagOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title="Edit indicator"
        description="Changes are recorded in the audit log. Where the record came from stays as it was."
      />
      <Card className="max-w-3xl">
        <CardContent>
          <IndicatorForm
            mode="edit"
            indicator={indicator}
            tagOptions={tags.map((tag) => tag.name)}
          />
        </CardContent>
      </Card>
    </>
  );
}
