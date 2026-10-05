import { ArrowLeft, ExternalLink } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DetailRow as Row } from "@/components/ui/detail-list";
import { AlertStatusBadge, OriginBadge, SeverityBadge } from "@/components/ui/domain-badges";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { alertListHref } from "@/lib/alerts/url";
import { getPageAuthContext } from "@/lib/auth/session";
import { formatDateTime } from "@/lib/format";
import { getTechniqueDetail, parseTechniqueId, type TechniqueDetail } from "@/lib/mitre/service";

export default async function TechniquePage({ params }: PageProps<"/mitre/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { id } = await params;
  if (!parseTechniqueId(id)) notFound();

  let technique: TechniqueDetail | null = null;
  try {
    technique = await getTechniqueDetail(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!technique) notFound();

  const canReadAlerts = auth.permissions.has("alerts:read");

  return (
    <>
      <title>{`${technique.id} ${technique.name} · MITRE ATT&CK · ArcRadar`}</title>

      <Link
        href="/mitre"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        ATT&amp;CK matrix
      </Link>

      <div className="mb-6 min-w-0 space-y-2">
        <h1
          className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
          data-testid="record-title"
        >
          <span className="font-mono">{technique.id}</span> {technique.name}
        </h1>
        <p className="text-sm text-muted">
          {technique.observed
            ? `Named by ${technique.observed.alert_count} ${technique.observed.alert_count === 1 ? "alert" : "alerts"} in this workspace.`
            : "No alert in this workspace names this technique."}{" "}
          The description below is MITRE reference text, not intelligence about your environment.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Alerts that name it</CardTitle>
            </CardHeader>
            <CardContent>
              {!canReadAlerts ? (
                <p className="text-sm text-muted">You do not have access to alerts.</p>
              ) : technique.alerts.length === 0 ? (
                <p className="text-sm text-muted">
                  Nothing yet. When a sensor alert maps to this technique, it is listed here.
                </p>
              ) : (
                <div className="space-y-3">
                  <ul className="divide-y divide-border">
                    {technique.alerts.map((alert) => (
                      <li key={alert.id} className="flex flex-wrap items-center gap-2 py-2.5">
                        <Link
                          href={`/alerts/${alert.id}`}
                          className="min-w-0 flex-1 font-medium [overflow-wrap:anywhere] hover:underline"
                        >
                          {alert.title}
                        </Link>
                        <SeverityBadge severity={alert.severity} />
                        <AlertStatusBadge status={alert.status} />
                        <OriginBadge origin={alert.origin} />
                        <span className="text-xs text-muted">
                          {formatDateTime(alert.created_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                  <Link
                    href={alertListHref({}, { technique: technique.id })}
                    className={buttonClasses({ variant: "secondary" })}
                  >
                    Open all {technique.alert_total} in the alert list
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {technique.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {technique.description}
                </p>
              ) : (
                <p className="text-sm text-muted">
                  No description is stored here. The ATT&amp;CK page has the full write-up.
                </p>
              )}
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
                <Row label="Id">
                  <span className="font-mono">{technique.id}</span>
                </Row>
                <Row label="Tactics">
                  <span className="flex flex-wrap gap-1.5">
                    {technique.tactics.length === 0 ? (
                      <span className="text-muted">Not recorded</span>
                    ) : (
                      technique.tactics.map((tactic) => (
                        <Badge key={tactic} tone="violet">
                          {tactic}
                        </Badge>
                      ))
                    )}
                  </span>
                </Row>
                {technique.parent_id && (
                  <Row label="Parent technique">
                    <Link
                      href={`/mitre/${technique.parent_id}`}
                      className="font-mono text-primary hover:underline"
                    >
                      {technique.parent_id}
                    </Link>
                  </Row>
                )}
                {technique.observed && (
                  <Row label="Last seen">{formatDateTime(technique.observed.last_seen)}</Row>
                )}
                {technique.url && (
                  <Row label="Reference">
                    <a
                      href={technique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      attack.mitre.org
                      <ExternalLink aria-hidden className="size-3.5" />
                      <span className="sr-only"> (opens in a new tab)</span>
                    </a>
                  </Row>
                )}
              </dl>
            </CardContent>
          </Card>

          {technique.subtechniques.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Sub-techniques</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1.5 text-sm">
                  {technique.subtechniques.map((sub) => (
                    <li key={sub.id}>
                      <Link href={`/mitre/${sub.id}`} className="hover:underline">
                        <span className="font-mono">{sub.id}</span> {sub.name}
                      </Link>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
