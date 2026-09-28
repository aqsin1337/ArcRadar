import { ArrowLeft, Pencil } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DeleteRecordButton } from "@/components/ui/delete-record-button";
import {
  LinkedIndicatorList,
  RecordChips,
  ValueChips,
} from "@/components/threat-intel/linked-records";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import { CampaignStatusBadge, OriginBadge } from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getActor, isEntityId } from "@/lib/threat-intel/service";
import type { ActorDetail } from "@/lib/threat-intel/types";

export default async function ThreatActorPage({ params }: PageProps<"/threat-actors/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isEntityId(id)) notFound();

  let actor: ActorDetail | null = null;
  try {
    actor = await getActor(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!actor) notFound();

  const canWrite = auth.permissions.has("threat_intel:write");

  return (
    <>
      <title>{`${actor.name} · Threat actors · ArcRadar`}</title>

      <Link
        href="/threat-actors"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All threat actors
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <h1
            className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
            data-testid="record-title"
          >
            {actor.name}
          </h1>
          {actor.aliases.length > 0 && (
            <p className="text-sm text-muted [overflow-wrap:anywhere]">
              Also known as {actor.aliases.join(", ")}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <OriginBadge origin={actor.origin} />
          </div>
        </div>
        {canWrite && (
          <div className="flex shrink-0 items-center gap-2">
            <Link
              href={`/threat-actors/${actor.id}/edit`}
              className={buttonClasses({ variant: "secondary" })}
            >
              <Pencil aria-hidden className="size-4" />
              Edit
            </Link>
            <DeleteRecordButton
              endpoint={`/api/threat-actors/${actor.id}`}
              listHref="/threat-actors"
              noun="threat actor"
              name={actor.name}
              consequence="Its links to malware, campaigns, techniques and indicators are removed; those records stay."
            />
          </div>
        )}
      </div>

      <ProvenanceNotice origin={actor.origin} className="mb-6" />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {actor.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {actor.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Malware</CardTitle>
            </CardHeader>
            <CardContent>
              <RecordChips
                empty="No malware families are linked."
                items={actor.malware.map((item) => ({
                  id: item.id,
                  label: item.name,
                  href: `/malware/${item.id}`,
                  origin: item.origin,
                  detail: item.malware_type,
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Campaigns</CardTitle>
            </CardHeader>
            <CardContent>
              <RecordChips
                empty="No campaigns are linked."
                items={actor.campaigns.map((item) => ({
                  id: item.id,
                  label: item.name,
                  href: `/campaigns/${item.id}`,
                  origin: item.origin,
                  detail: <CampaignStatusBadge status={item.status} />,
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <RecordChips
                empty="No ATT&CK techniques are linked."
                items={actor.techniques.map((item) => ({
                  id: item.id,
                  label: item.id,
                  href: `/mitre/${item.id}`,
                  detail: item.name,
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              <LinkedIndicatorList indicators={actor.indicators} />
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Profile</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Motivation">
                  {actor.motivation ?? <span className="text-muted">Unknown</span>}
                </Row>
                <Row label="Attributed to">
                  {actor.attribution_country ?? <span className="text-muted">Not attributed</span>}
                </Row>
                <Row label="Target industries">
                  <ValueChips values={actor.target_industries} empty="Not recorded" />
                </Row>
                <Row label="Target countries">
                  <ValueChips values={actor.target_countries} empty="Not recorded" />
                </Row>
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="First seen">
                  {actor.first_seen ? <Time iso={actor.first_seen} /> : "—"}
                </Row>
                <Row label="Last seen">
                  {actor.last_seen ? <Time iso={actor.last_seen} /> : "—"}
                </Row>
                <Row label="Added">
                  <Time iso={actor.created_at} />
                </Row>
                <Row label="Updated">
                  <Time iso={actor.updated_at} />
                </Row>
                <Row label="Added by">{actor.created_by_name ?? "—"}</Row>
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
