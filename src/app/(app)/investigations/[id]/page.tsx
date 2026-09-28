import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAiAvailability } from "@/lib/ai/service";
import { ChecklistPanel } from "@/components/investigations/checklist-panel";
import { InvestigationControls } from "@/components/investigations/investigation-controls";
import { InvestigationTimeline } from "@/components/investigations/investigation-timeline";
import { EvidencePanel } from "@/components/investigations/evidence-panel";
import { LinkedAlerts, LinkedIndicators } from "@/components/investigations/linked-items";
import { NotesPanel } from "@/components/investigations/notes-panel";
import { TagChips } from "@/components/indicators/tag-chips";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DeleteRecordButton } from "@/components/ui/delete-record-button";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import {
  InvestigationStatusBadge,
  OriginBadge,
  PriorityBadge,
} from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { personLabel } from "@/lib/format";
import { listTagOptions } from "@/lib/indicators/service";
import { getChecklist, getInvestigation, isInvestigationId } from "@/lib/investigations/service";
import type { InvestigationDetail } from "@/lib/investigations/types";
import { findTeamMembers } from "@/lib/team/repository";

export default async function InvestigationPage({ params }: PageProps<"/investigations/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("investigations:read")) return <AccessDenied />;

  const { id } = await params;
  if (!isInvestigationId(id)) notFound();

  let investigation: InvestigationDetail | null = null;
  try {
    investigation = await getInvestigation(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!investigation) notFound();

  const canWrite = auth.permissions.has("investigations:write");
  const canUseAi = auth.permissions.has("ai:use");
  const [people, tags, checklist, aiReady] = await Promise.all([
    canWrite ? findTeamMembers(auth.supabase, "investigations:write") : Promise.resolve([]),
    canWrite ? listTagOptions(auth.supabase) : Promise.resolve([]),
    getChecklist(auth.supabase, investigation.id),
    canUseAi ? getAiAvailability(auth.supabase).then((a) => a.ready) : Promise.resolve(false),
  ]);

  return (
    <>
      <title>{`${investigation.title} · Investigations · ArcRadar`}</title>

      <Link
        href="/investigations"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All investigations
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <h1
            className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
            data-testid="investigation-title"
          >
            {investigation.title}
          </h1>
          <div className="flex flex-wrap items-center gap-2">
            <span data-testid="investigation-status">
              <InvestigationStatusBadge status={investigation.status} />
            </span>
            <PriorityBadge priority={investigation.priority} />
            <OriginBadge origin={investigation.origin} />
          </div>
          {investigation.tags.length > 0 && <TagChips tags={investigation.tags} />}
        </div>
        {auth.permissions.has("investigations:delete") && (
          <DeleteRecordButton
            endpoint={`/api/investigations/${investigation.id}`}
            listHref="/investigations"
            noun="investigation"
            name={investigation.title}
            consequence="Its notes, evidence references and history go with it. The indicators and alerts attached to it stay."
          />
        )}
      </div>

      <ProvenanceNotice origin={investigation.origin} className="mb-6" />

      {canWrite && (
        <Card className="mb-4">
          <CardHeader>
            <CardTitle>Manage</CardTitle>
          </CardHeader>
          <CardContent>
            <InvestigationControls
              investigation={{
                id: investigation.id,
                title: investigation.title,
                description: investigation.description,
                status: investigation.status,
                priority: investigation.priority,
                analyst_id: investigation.analyst_id,
                tags: investigation.tags.map((tag) => tag.name),
              }}
              people={people}
              tagOptions={tags.map((tag) => tag.name)}
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
              {investigation.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {investigation.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <LinkedAlerts
                investigationId={investigation.id}
                items={investigation.alerts}
                canWrite={canWrite}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              <LinkedIndicators
                investigationId={investigation.id}
                items={investigation.indicators}
                canWrite={canWrite}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Notes</CardTitle>
            </CardHeader>
            <CardContent>
              <NotesPanel
                investigationId={investigation.id}
                notes={investigation.notes}
                currentUserId={auth.user.id}
                canWrite={canWrite}
                canModerate={auth.permissions.has("investigations:delete")}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Evidence</CardTitle>
            </CardHeader>
            <CardContent>
              <EvidencePanel
                investigationId={investigation.id}
                items={investigation.evidence}
                canWrite={canWrite}
              />
            </CardContent>
          </Card>

          {(checklist.length > 0 || canUseAi || canWrite) && (
            <Card>
              <CardHeader>
                <CardTitle>Checklist</CardTitle>
              </CardHeader>
              <CardContent>
                <ChecklistPanel
                  investigationId={investigation.id}
                  items={checklist}
                  canWrite={canWrite}
                  canUseAi={canUseAi}
                  aiReady={aiReady}
                />
              </CardContent>
            </Card>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Status">
                  <InvestigationStatusBadge status={investigation.status} />
                </Row>
                <Row label="Priority">
                  <PriorityBadge priority={investigation.priority} />
                </Row>
                <Row label="Analyst">
                  <span data-testid="investigation-analyst">
                    {investigation.analyst ? (
                      personLabel(investigation.analyst)
                    ) : (
                      <span className="text-muted">Unassigned</span>
                    )}
                  </span>
                </Row>
                <Row label="Opened by">{investigation.created_by_name ?? "—"}</Row>
                <Row label="Opened">
                  <Time iso={investigation.created_at} />
                </Row>
                <Row label="Updated">
                  <Time iso={investigation.updated_at} />
                </Row>
                {investigation.closed_at && (
                  <Row label="Closed">
                    <Time iso={investigation.closed_at} />
                  </Row>
                )}
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <InvestigationTimeline entries={investigation.timeline} />
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
