import { ArrowLeft, Search } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { AiAnalysisPanel } from "@/components/alerts/ai-analysis-panel";
import { AlertActions } from "@/components/alerts/alert-actions";
import { ResponseActionsPanel } from "@/components/alerts/response-actions-panel";
import { TechniqueChips } from "@/components/alerts/technique-chips";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DeleteRecordButton } from "@/components/ui/delete-record-button";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import {
  AlertStatusBadge,
  InvestigationStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getAiAvailability, listAlertAnalyses } from "@/lib/ai/service";
import { buildAlertTimeline } from "@/lib/alerts/timeline";
import { getAlert, isAlertId } from "@/lib/alerts/service";
import type { AlertDetail } from "@/lib/alerts/types";
import { getPageAuthContext } from "@/lib/auth/session";
import { personLabel } from "@/lib/format";
import { INDICATOR_TYPE_LABELS } from "@/lib/indicators/constants";
import { intelHref, intelKindOf } from "@/lib/intel/constants";
import { listAlertResponseActions, listResponseActions } from "@/lib/response-actions/service";
import { findTeamMembers } from "@/lib/team/repository";

const MAX_PAYLOAD_CHARS = 4000;

export default async function AlertPage({ params }: PageProps<"/alerts/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("alerts:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isAlertId(id)) notFound();

  let alert: AlertDetail | null = null;
  try {
    alert = await getAlert(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!alert) notFound();

  const canWrite = auth.permissions.has("alerts:write");
  const canInvestigate = auth.permissions.has("investigations:write") && canWrite;
  const canUseAi = auth.permissions.has("ai:use");
  const people = canWrite ? await findTeamMembers(auth.supabase, "alerts:write") : [];
  const lookupKind = alert.indicator ? intelKindOf(alert.indicator.type) : null;
  const timeline = buildAlertTimeline(alert);
  const now = new Date();

  const [analyses, aiReady, responseActions, responseActionCatalog] = await Promise.all([
    listAlertAnalyses(auth.supabase, alert.id),
    canUseAi ? getAiAvailability(auth.supabase).then((a) => a.ready) : Promise.resolve(false),
    listAlertResponseActions(auth.supabase, alert.id),
    canWrite ? listResponseActions(auth.supabase) : Promise.resolve([]),
  ]);

  const payload = alert.event ? JSON.stringify(alert.event.payload, null, 2) : "";

  return (
    <>
      <title>{`${alert.title} · Alerts · ArcRadar`}</title>

      <Link
        href="/alerts"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All alerts
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <h1
            className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
            data-testid="alert-title"
          >
            {alert.title}
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <span data-testid="alert-status">
              <AlertStatusBadge status={alert.status} />
            </span>
            <OriginBadge origin={alert.origin} />
            <Badge tone="slate">{alert.source}</Badge>
          </div>
        </div>
        {auth.permissions.has("alerts:delete") && (
          <DeleteRecordButton
            endpoint={`/api/alerts/${alert.id}`}
            listHref="/alerts"
            noun="alert"
            name={alert.title}
            consequence="It is also removed from any investigation it was attached to; those stay."
          />
        )}
      </div>

      <ProvenanceNotice
        origin={alert.origin}
        externalText={`Delivered by ${alert.source}: telemetry sent to ArcRadar's ingest endpoint, not demo or local data. The raw event is further down this page.`}
        className="mb-6"
      />

      {alert.primary_alert && (
        <Alert tone="info" className="mb-4">
          This is a duplicate of{" "}
          <Link href={`/alerts/${alert.primary_alert.id}`} className="font-medium underline">
            {alert.primary_alert.title}
          </Link>
          . It was linked automatically because the two matched the same source, title, asset and
          indicator within an hour of each other.
        </Alert>
      )}

      {canWrite && (
        <Card className="mb-4">
          <CardHeader>
            <CardTitle>Workflow</CardTitle>
          </CardHeader>
          <CardContent>
            <AlertActions
              alert={{
                id: alert.id,
                title: alert.title,
                status: alert.status,
                assigned_to: alert.assigned_to,
                indicator_id: alert.indicator_id,
              }}
              people={people}
              canInvestigate={canInvestigate}
            />
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {alert.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {alert.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Related indicator</CardTitle>
            </CardHeader>
            <CardContent>
              {alert.indicator ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone="slate">{INDICATOR_TYPE_LABELS[alert.indicator.type]}</Badge>
                    <VerdictBadge verdict={alert.indicator.verdict} />
                    <SeverityBadge severity={alert.indicator.severity} />
                  </div>
                  <Link
                    href={`/indicators/${alert.indicator.id}`}
                    className="block font-mono text-sm font-medium [overflow-wrap:anywhere] text-primary hover:underline"
                  >
                    {alert.indicator.value}
                  </Link>
                  {lookupKind && (
                    <Link
                      href={intelHref(lookupKind, alert.indicator.value)}
                      prefetch={false}
                      className={buttonClasses({ variant: "secondary", size: "sm" })}
                    >
                      <Search aria-hidden className="size-4" />
                      Look it up
                    </Link>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted">This alert is not linked to an indicator.</p>
              )}
            </CardContent>
          </Card>

          {alert.event && (
            <Card>
              <CardHeader>
                <CardTitle>Event</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <dl className="divide-y divide-border">
                  <Row label="Title">{alert.event.title}</Row>
                  <Row label="Type">{alert.event.event_type}</Row>
                  <Row label="Source">{alert.event.source}</Row>
                  <Row label="Severity">
                    <SeverityBadge severity={alert.event.severity} />
                  </Row>
                  <Row label="Occurred">
                    <Time iso={alert.event.occurred_at} />
                  </Row>
                </dl>
                <details className="rounded-lg border border-border">
                  <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
                    Raw event data
                  </summary>
                  <pre className="max-h-80 overflow-auto border-t border-border p-3 font-mono text-xs">
                    {payload.slice(0, MAX_PAYLOAD_CHARS)}
                    {payload.length > MAX_PAYLOAD_CHARS ? "\n… (truncated)" : ""}
                  </pre>
                </details>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Investigations</CardTitle>
            </CardHeader>
            <CardContent>
              {alert.investigations.length === 0 ? (
                <p className="text-sm text-muted">
                  This alert is not part of an investigation yet.
                </p>
              ) : (
                <ul className="divide-y divide-border">
                  {alert.investigations.map((investigation) => (
                    <li
                      key={investigation.id}
                      className="flex flex-wrap items-center gap-2 py-2 text-sm first:pt-0 last:pb-0"
                    >
                      <Link
                        href={`/investigations/${investigation.id}`}
                        className="font-medium text-primary [overflow-wrap:anywhere] hover:underline"
                      >
                        {investigation.title}
                      </Link>
                      <span className="ml-auto">
                        <InvestigationStatusBadge status={investigation.status} />
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <AiAnalysisPanel
            alertId={alert.id}
            canUse={canUseAi}
            ready={aiReady}
            initialLatest={analyses.latest}
            now={now}
          />

          {(responseActions.length > 0 || canWrite) && (
            <Card>
              <CardHeader>
                <CardTitle>Response actions</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponseActionsPanel
                  alertId={alert.id}
                  entries={responseActions}
                  catalog={responseActionCatalog}
                  canWrite={canWrite}
                  now={now}
                />
              </CardContent>
            </Card>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Severity">
                  <SeverityBadge severity={alert.severity} />
                </Row>
                <Row label="Status">
                  <AlertStatusBadge status={alert.status} />
                </Row>
                {alert.ai_fp_score !== null && (
                  <Row label="AI false positive score">
                    <span data-testid="alert-ai-fp-score">{Math.round(alert.ai_fp_score)}%</span>
                  </Row>
                )}
                {alert.matched_rule && (
                  <Row label="Matched rule">
                    <span data-testid="alert-matched-rule">
                      {alert.matched_rule.name}{" "}
                      <span className="font-mono text-xs text-muted">#{alert.matched_rule.id}</span>
                    </span>
                  </Row>
                )}
                <Row label="Assigned to">
                  <span data-testid="alert-assignee">
                    {alert.assignee ? (
                      personLabel(alert.assignee)
                    ) : (
                      <span className="text-muted">Nobody</span>
                    )}
                  </span>
                </Row>
                <Row label="Source">{alert.source}</Row>
                <Row label="Asset">
                  {alert.asset ? (
                    <span data-testid="alert-asset">
                      {alert.asset.name}
                      {alert.asset.ip_address && (
                        <span className="block font-mono text-xs font-normal text-muted">
                          {alert.asset.ip_address}
                        </span>
                      )}
                      {alert.asset.os && (
                        <span className="block text-xs font-normal text-muted">
                          {alert.asset.os}
                        </span>
                      )}
                    </span>
                  ) : (
                    <span className="text-muted">Not recorded</span>
                  )}
                </Row>
                {alert.techniques.length > 0 && (
                  <Row label="Techniques">
                    <TechniqueChips items={alert.techniques} />
                  </Row>
                )}
                <Row label="Created by">{alert.created_by_name ?? "—"}</Row>
              </dl>
            </CardContent>
          </Card>

          {alert.duplicates.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Duplicates ({alert.duplicates.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="mb-3 text-sm text-muted">
                  Later occurrences of the same alert, linked here instead of opening a fresh one.
                </p>
                <ul className="divide-y divide-border">
                  {alert.duplicates.map((duplicate) => (
                    <li
                      key={duplicate.id}
                      className="flex flex-wrap items-center gap-2 py-2 text-sm"
                    >
                      <Link
                        href={`/alerts/${duplicate.id}`}
                        className="min-w-0 flex-1 [overflow-wrap:anywhere] text-primary hover:underline"
                      >
                        {duplicate.title}
                      </Link>
                      <Time iso={duplicate.created_at} />
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-4 border-l border-border pl-4">
                {timeline.map((entry, index) => (
                  <li key={`${entry.title}-${entry.at}-${index}`} className="relative space-y-0.5">
                    <span
                      aria-hidden
                      className="absolute top-1.5 -left-[21px] size-2 rounded-full border border-border bg-surface-2"
                    />
                    <p className="text-xs text-muted">
                      <Time iso={entry.at} />
                    </p>
                    <p className="text-sm font-medium">{entry.title}</p>
                    {entry.detail && (
                      <p className="text-xs text-muted [overflow-wrap:anywhere]">{entry.detail}</p>
                    )}
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
