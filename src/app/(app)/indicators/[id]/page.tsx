import { ArrowLeft, ArrowRight, Pencil } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { notFound } from "next/navigation";
import { DeleteIndicatorButton } from "@/components/indicators/delete-indicator-button";
import { TagChips } from "@/components/indicators/tag-chips";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfidenceMeter } from "@/components/ui/confidence-meter";
import {
  IndicatorStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { formatDateTime } from "@/lib/format";
import { INDICATOR_TYPE_LABELS, INDICATOR_TYPE_SHORT_LABELS } from "@/lib/indicators/constants";
import { getIndicator, isIndicatorId } from "@/lib/indicators/service";
import type { IndicatorDetail, LinkedEntity } from "@/lib/indicators/types";
import type { DataOrigin, RelationshipType } from "@/types/domain";

const RELATIONSHIP_VERBS: Record<RelationshipType, string> = {
  resolves_to: "resolves to",
  communicates_with: "communicates with",
  downloads: "downloads",
  hosted_on: "is hosted on",
  related_to: "is related to",
};

const PROVENANCE_NOTICE: Record<DataOrigin, { tone: "warning" | "info" | null; text: string }> = {
  demo: {
    tone: "warning",
    text: "This is demo data: a sample record for demonstration, not live intelligence.",
  },
  local: {
    tone: "info",
    text: "Local data: entered by your team and not verified by an external provider.",
  },
  external: { tone: null, text: "" },
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 py-2 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-right font-medium break-words">{children}</dd>
    </div>
  );
}

function Time({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={iso}>
      {formatDateTime(iso)}
    </time>
  );
}

function EntityList({ title, items }: { title: string; items: LinkedEntity[] }) {
  return (
    <div className="space-y-1.5">
      <h3 className="text-xs font-semibold tracking-wide text-muted uppercase">{title}</h3>
      {items.length === 0 ? (
        <p className="text-sm text-muted">None linked.</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {items.map((item) => (
            <li key={item.id} className="inline-flex items-center gap-1.5 text-sm">
              <span className="font-medium">{item.name}</span>
              {item.origin === "demo" && <OriginBadge origin="demo" />}
            </li>
          ))}
        </ul>
      )}
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
  const notice = PROVENANCE_NOTICE[indicator.origin];
  const hasLinks =
    indicator.threat_actors.length + indicator.campaigns.length + indicator.malware.length > 0;

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

      {notice.tone && (
        <Alert tone={notice.tone} className="mb-6">
          {notice.text}
        </Alert>
      )}

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
                        <Badge tone="slate" className="ml-auto">
                          {INDICATOR_TYPE_SHORT_LABELS[link.other.type]}
                        </Badge>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Linked intelligence</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {hasLinks ? null : (
                <p className="text-sm text-muted">
                  Not linked to any threat actor, campaign or malware family.
                </p>
              )}
              {hasLinks && (
                <>
                  <EntityList title="Threat actors" items={indicator.threat_actors} />
                  <EntityList title="Campaigns" items={indicator.campaigns} />
                  <EntityList title="Malware" items={indicator.malware} />
                </>
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
