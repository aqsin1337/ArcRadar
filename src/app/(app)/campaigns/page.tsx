import { Megaphone, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { CampaignFilters } from "@/components/threat-intel/threat-filters";
import { CampaignTable } from "@/components/threat-intel/threat-tables";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseCampaignListParams } from "@/lib/threat-intel/schema";
import { listCampaigns } from "@/lib/threat-intel/service";
import { campaignList } from "@/lib/threat-intel/url";

export const metadata: Metadata = { title: "Campaigns" };

export default async function CampaignsPage({ searchParams }: PageProps<"/campaigns">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseCampaignListParams(await searchParams);
  const { items, pagination } = await listCampaigns(auth.supabase, query);
  const canWrite = auth.permissions.has("threat_intel:write");

  const newCampaign = canWrite && (
    <Link href="/campaigns/new" className={buttonClasses()}>
      <Plus aria-hidden className="size-4" />
      New campaign
    </Link>
  );

  return (
    <>
      <PageHeader
        title="Campaigns"
        description="Coordinated activity over time, with the actors behind it and the indicators seen in it. Every record shows where it came from."
        actions={newCampaign}
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}
        <CampaignFilters state={query} />
        <ListResults
          pagination={pagination}
          count={items.length}
          filtered={campaignList.hasActive(query)}
          noun={["campaign", "campaigns"]}
          listHref="/campaigns"
          hrefForPage={(page) => campaignList.href(query, { page })}
          empty={{
            icon: Megaphone,
            title: "No campaigns yet",
            description: canWrite
              ? "Add one when you start tracking a piece of coordinated activity."
              : "No campaigns have been added yet.",
            action: newCampaign || undefined,
          }}
        >
          <CampaignTable items={items} state={query} />
        </ListResults>
      </div>
    </>
  );
}
