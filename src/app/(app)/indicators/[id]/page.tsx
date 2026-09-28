import { ArrowLeft, ArrowRight, Pencil } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DeleteIndicatorButton } from "@/components/indicators/delete-indicator-button";
import { IndicatorLinksEditor } from "@/components/indicators/indicator-links-editor";
import {
  AddRelationshipForm,
  RemoveRelationshipButton,
} from "@/components/indicators/relationship-controls";
import { TagChips } from "@/components/indicators/tag-chips";
import { VerdictRecommendationPanel } from "@/components/indicators/verdict-recommendation-panel";
import { RecordChips } from "@/components/threat-intel/linked-records";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfidenceMeter } from "@/components/ui/confidence-meter";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import {
  IndicatorStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { getAiAvailability, listSubjectAnalyses } from "@/lib/ai/service";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import {
  INDICATOR_TYPE_LABELS,
  INDICATOR_TYPE_SHORT_LABELS,
  RELATIONSHIP_VERBS,
} from "@/lib/indicators/constants";
import { getIndicator, isIndicatorId } from "@/lib/indicators/service";
import type { IndicatorDetail, LinkedEntity } from "@/lib/indicators/types";
import { getLinkOptions } from "@/lib/threat-intel/service";

/** Threat actors, campaigns or malware linked to the indicator, each a link to its page with its provenance. */
function EntityList({
  title,
  items,
  basePath,
}: {
  title: string;
  items: LinkedEntity[];
  basePath: string;
}) {
  return (
    <div className="space-y-1.5">
      <h3 className="text-xs font-semibold tracking-wide text-muted uppercase">{title}</h3>
      <RecordChips
        empty="None linked."
        items={items.map((item) => ({
          id: item.id,
          label: item.name,
          href: `${basePath}/${item.id}`,
          origin: item.origin,
        }))}
      />
    </div>
  );
}

export default async function IndicatorPage({ params }: PageProps<"/indicators/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("indicators:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isIndicatorId(id)) notFound();

  let indicator: IndicatorDetail | null = null;
  try {
    indicator = await getIndicator(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!indicator) notFound();

  const canWrite = auth.permissions.has("indicators:write");
  const canDelete = auth.permissions.has("indicators:delete");
  const canUseAi = auth.permissions.has("ai:use");
  // Editors need the choices to link to; readers of intelligence records only need the names above.
  const linkOptions =
    canWrite && auth.permissions.has("threat_intel:read")
      ? await getLinkOptions(auth.supabase)
      : null;
  const [verdictAnalyses, aiReady] = await Promise.all([
    listSubjectAnalyses(auth.supabase, "indicator", indicator.id),
    canUseAi ? getAiAvailability(auth.supabase).then((a) => a.ready) : Promise.resolve(false),
  ]);
  const now = new Date();

  return (
    <>
      <title>{`${indicator.value} · Indicators · ArcRadar`}</title>

      <Link
        href="/indicators"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All indicators
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <h1
            className="font-mono text-xl font-semibold break-all sm:text-2xl"
            data-testid="indicator-value"
          >
            {indicator.value}
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="slate">{INDICATOR_TYPE_LABELS[indicator.type]}</Badge>
            <OriginBadge origin={indicator.origin} />
            <VerdictBadge verdict={indicator.verdict} />
            <SeverityBadge severity={indicator.severity} />
          </div>
        </div>
        {(canWrite || canDelete) && (
          <div className="flex shrink-0 items-center gap-2">
            {canWrite && (
              <Link
                href={`/indicators/${indicator.id}/edit`}
                className={buttonClasses({ variant: "secondary" })}
              >
                <Pencil aria-hidden className="size-4" />
                Edit
              </Link>
            )}
            {canDelete && <DeleteIndicatorButton id={indicator.id} value={indicator.value} />}
          </div>
        )}
      </div>

      <ProvenanceNotice origin={indicator.origin} className="mb-6" />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {indicator.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {indicator.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Relationships</CardTitle>
            </CardHeader>
            <CardContent>
              {indicator.relationships.length === 0 ? (
                <p className="text-sm text-muted">No related indicators.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {indicator.relationships.map((link) => {
                    const other = (
                      <Link
                        href={`/indicators/${link.other.id}`}
                        className="font-mono text-sm font-medium break-all text-primary hover:underline"
                      >
                        {link.other.value}
                        <span className="sr-only">
                          {" "}
                          ({INDICATOR_TYPE_SHORT_LABELS[link.other.type]})
                        </span>
                      </Link>
                    );
                    return (
                      <li
                        key={link.id}
                        className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2.5 text-sm"
                      >
                        {link.direction === "outgoing" ? (
                          <ArrowRight aria-hidden className="size-4 shrink-0 text-muted" />
                        ) : (
                          <ArrowLeft aria-hidden className="size-4 shrink-0 text-muted" />
                        )}
                        {link.direction === "outgoing" ? (
                          <>
                            <span className="text-muted">
                              {RELATIONSHIP_VERBS[link.relationship]}
                            </span>
                            {other}
                          </>
                        ) : (
                          <>
                            {other}
                            <span className="text-muted">
                              {RELATIONSHIP_VERBS[link.relationship]} this indicator
                            </span>
                          </>
                        )}
                        <span className="ml-auto inline-flex items-center gap-1">
                          <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[link.other.type]}</Badge>
                          {canWrite && (
                            <RemoveRelationshipButton
                              indicatorId={indicator.id}
                              relationshipId={link.id}
                              label={`Remove the relationship with ${link.other.value}`}
                            />
                          )}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
              {canWrite && (
                <div className="mt-4">
                  <AddRelationshipForm
                    indicatorId={indicator.id}
                    related={indicator.relationships.map((link) => link.other.id)}
                  />
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Linked intelligence</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <EntityList
                title="Threat actors"
                items={indicator.threat_actors}
                basePath="/threat-actors"
              />
              <EntityList title="Campaigns" items={indicator.campaigns} basePath="/campaigns" />
              <EntityList title="Malware" items={indicator.malware} basePath="/malware" />
              {linkOptions && (
                <IndicatorLinksEditor
                  indicatorId={indicator.id}
                  options={linkOptions}
                  initial={{
                    actor_ids: indicator.threat_actors.map((item) => item.id),
                    campaign_ids: indicator.campaigns.map((item) => item.id),
                    malware_ids: indicator.malware.map((item) => item.id),
                  }}
                />
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Verdict">
                  <VerdictBadge verdict={indicator.verdict} />
                </Row>
                <Row label="Severity">
                  <SeverityBadge severity={indicator.severity} />
                </Row>
                <Row label="Confidence">
                  <ConfidenceMeter value={indicator.confidence} />
                </Row>
                <Row label="Status">
                  <IndicatorStatusBadge status={indicator.status} />
                </Row>
              </dl>
            </CardContent>
          </Card>

          {(canUseAi || verdictAnalyses.latest.verdict_recommendation) && (
            <Card>
              <CardHeader>
                <CardTitle>AI verdict recommendation</CardTitle>
              </CardHeader>
              <CardContent>
                <VerdictRecommendationPanel
                  indicatorId={indicator.id}
                  canUse={canUseAi}
                  canApply={canWrite}
                  ready={aiReady}
                  initial={verdictAnalyses.latest.verdict_recommendation ?? null}
                  now={now}
                />
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Tags</CardTitle>
            </CardHeader>
            <CardContent>
              <TagChips tags={indicator.tags} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="First seen">
                  <Time iso={indicator.first_seen} />
                </Row>
                <Row label="Last seen">
                  <Time iso={indicator.last_seen} />
                </Row>
                <Row label="Source">{indicator.source}</Row>
                <Row label="Added">
                  <Time iso={indicator.created_at} />
                </Row>
                <Row label="Updated">
                  <Time iso={indicator.updated_at} />
                </Row>
                <Row label="Added by">{indicator.created_by_name ?? "—"}</Row>
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
