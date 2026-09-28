import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CampaignForm } from "@/components/threat-intel/campaign-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getCampaign, getLinkOptions, isEntityId } from "@/lib/threat-intel/service";
import type { CampaignDetail } from "@/lib/threat-intel/types";

export const metadata: Metadata = { title: "Edit campaign" };

export default async function EditCampaignPage({ params }: PageProps<"/campaigns/[id]/edit">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const { id } = await params;
  if (!isEntityId(id)) notFound();
  if (!auth.permissions.has("threat_intel:write")) {
    return (
      <AccessDenied
        title="You can't edit campaigns"
        description="Editing threat intelligence needs the administrator role."
        action={
          <Link href={`/campaigns/${id}`} className={buttonClasses({ variant: "secondary" })}>
            Back to the campaign
          </Link>
        }
      />
    );
  }

  let campaign: CampaignDetail | null = null;
  try {
    campaign = await getCampaign(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!campaign) notFound();

  const options = await getLinkOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title={`Edit ${campaign.name}`}
        description="Changes are recorded in the audit log."
      />
      <Card className="max-w-3xl">
        <CardContent>
          <CampaignForm mode="edit" campaign={campaign} options={options} />
        </CardContent>
      </Card>
    </>
  );
}
