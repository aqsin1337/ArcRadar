import { ArrowLeft, Pencil } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DeleteRecordButton } from "@/components/ui/delete-record-button";
import { LinkedIndicatorList, RecordChips } from "@/components/threat-intel/linked-records";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import { CampaignStatusBadge, OriginBadge } from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getCampaign, isEntityId } from "@/lib/threat-intel/service";
import type { CampaignDetail } from "@/lib/threat-intel/types";

export default async function CampaignPage({ params }: PageProps<"/campaigns/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isEntityId(id)) notFound();

  let campaign: CampaignDetail | null = null;
  try {
    campaign = await getCampaign(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!campaign) notFound();

  const canWrite = auth.permissions.has("threat_intel:write");

  return (
    <>
      <title>{`${campaign.name} · Campaigns · ArcRadar`}</title>

      <Link
        href="/campaigns"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All campaigns
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <h1
            className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
            data-testid="record-title"
          >
            {campaign.name}
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <CampaignStatusBadge status={campaign.status} />
            <OriginBadge origin={campaign.origin} />
          </div>
        </div>
        {canWrite && (
          <div className="flex shrink-0 items-center gap-2">
            <Link
              href={`/campaigns/${campaign.id}/edit`}
              className={buttonClasses({ variant: "secondary" })}
            >
              <Pencil aria-hidden className="size-4" />
              Edit
            </Link>
            <DeleteRecordButton
              endpoint={`/api/campaigns/${campaign.id}`}
              listHref="/campaigns"
              noun="campaign"
              name={campaign.name}
              consequence="Its links to threat actors and indicators are removed; those records stay."
            />
          </div>
        )}
      </div>

      <ProvenanceNotice origin={campaign.origin} className="mb-6" />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {campaign.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {campaign.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat actors</CardTitle>
            </CardHeader>
            <CardContent>
              <RecordChips
                empty="No threat actors are linked."
                items={campaign.actors.map((item) => ({
                  id: item.id,
                  label: item.name,
                  href: `/threat-actors/${item.id}`,
                  origin: item.origin,
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              <LinkedIndicatorList indicators={campaign.indicators} />
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Status">
                  <CampaignStatusBadge status={campaign.status} />
                </Row>
                <Row label="First seen">
                  {campaign.first_seen ? <Time iso={campaign.first_seen} /> : "—"}
                </Row>
                <Row label="Last seen">
                  {campaign.last_seen ? <Time iso={campaign.last_seen} /> : "—"}
                </Row>
                <Row label="Added">
                  <Time iso={campaign.created_at} />
                </Row>
                <Row label="Updated">
                  <Time iso={campaign.updated_at} />
                </Row>
                <Row label="Added by">{campaign.created_by_name ?? "—"}</Row>
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
