import type { Metadata } from "next";
import Link from "next/link";
import { IndicatorForm } from "@/components/indicators/indicator-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { INDICATOR_TYPES } from "@/lib/indicators/constants";
import { listTagOptions } from "@/lib/indicators/service";
import { firstValues } from "@/lib/validation/query";

export const metadata: Metadata = { title: "New indicator" };

export default async function NewIndicatorPage({ searchParams }: PageProps<"/indicators/new">) {
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

  // A lookup page links here with the type and value it was looking at; anything odd is ignored.
  const { type, value } = firstValues(await searchParams);
  const knownType = INDICATOR_TYPES.find((known) => known === type);
  const defaults = {
    ...(knownType ? { type: knownType } : {}),
    ...(value && value.length <= 2048 ? { value: value.trim() } : {}),
  };

  const tags = await listTagOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title="New indicator"
        description="Record an observable you want to track. It is saved as local data and is checked for duplicates."
      />
      <Card className="max-w-3xl">
        <CardContent>
          <IndicatorForm
            mode="create"
            defaults={defaults}
            tagOptions={tags.map((tag) => tag.name)}
          />
        </CardContent>
      </Card>
    </>
  );
}
