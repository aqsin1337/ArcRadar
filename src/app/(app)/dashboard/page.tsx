import type { Metadata } from "next";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DistributionBars } from "@/components/ui/distribution-bars";
import {
  ORIGIN_DESCRIPTIONS,
  OriginBadge,
  SEVERITY_TONES,
  VERDICT_TONES,
  humanize,
} from "@/components/ui/domain-badges";
import { PageHeader } from "@/components/ui/page-header";
import { ActivityChart } from "@/components/dashboard/activity-chart";
import { DashboardFilters } from "@/components/dashboard/dashboard-filters";
import {
  AlertPanel,
  IndicatorPanel,
  InvestigationPanel,
  TopThreatActorsPanel,
} from "@/components/dashboard/panels";
import { StatTiles } from "@/components/dashboard/stat-tiles";
import { RefreshButton } from "@/components/refresh-button";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseDashboardParams } from "@/lib/dashboard/schema";
import { getDashboardData } from "@/lib/dashboard/service";
import { INDICATOR_TYPE_LABELS } from "@/lib/indicators/constants";
import { ROLE_NAMES } from "@/types/domain";

export const metadata: Metadata = { title: "Overview" };

/** "indicators:read", "indicators:write" -> [["indicators", ["read", "write"]]] */
function groupPermissions(permissions: Iterable<string>): [string, string[]][] {
  const groups = new Map<string, string[]>();
  for (const permission of permissions) {
    const [resource, action] = permission.split(":");
    groups.set(resource, [...(groups.get(resource) ?? []), action]);
  }
  return [...groups];
}

const RESOURCE_LABELS: Record<string, string> = {
  api_keys: "API keys",
  threat_intel: "Threat intelligence",
  audit: "Audit log",
};

export default async function DashboardPage({ searchParams }: PageProps<"/dashboard">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const { query, ignoredInvalid } = parseDashboardParams(await searchParams);
  const data = await getDashboardData(auth, query);
  const name = auth.profile.display_name ?? auth.user.email ?? "there";
  const access = groupPermissions(auth.permissions);

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Welcome, ${name}. Real counts from your workspace, refreshed on demand.`}
      />

      <div className="space-y-6">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <div className="flex flex-wrap items-end justify-between gap-3">
          <DashboardFilters query={query} />
          <RefreshButton label="Refresh" variant="secondary" />
        </div>

        <StatTiles counts={data.counts} days={query.days} />

        <div className="grid gap-4 lg:grid-cols-3">
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Threat activity</CardTitle>
              <CardDescription>Alerts raised and events received, by day.</CardDescription>
            </CardHeader>
            <CardContent>
              <ActivityChart data={data.activity} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Alert severity</CardTitle>
              <CardDescription>Every alert on record, by severity.</CardDescription>
            </CardHeader>
            <CardContent>
              <DistributionBars
                rows={data.severity_distribution.map((row) => ({
                  label: humanize(row.severity),
                  total: row.total,
                  tone: SEVERITY_TONES[row.severity],
                }))}
              />
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>IOC type distribution</CardTitle>
              <CardDescription>Every tracked indicator, by type.</CardDescription>
            </CardHeader>
            <CardContent>
              <DistributionBars
                rows={data.ioc_distribution.map((row) => ({
                  label: INDICATOR_TYPE_LABELS[row.type],
                  total: row.total,
                }))}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicator verdicts</CardTitle>
              <CardDescription>What the workspace has judged so far.</CardDescription>
            </CardHeader>
            <CardContent>
              <DistributionBars
                rows={data.verdict_distribution.map((row) => ({
                  label: humanize(row.verdict),
                  total: row.total,
                  tone: VERDICT_TONES[row.verdict],
                }))}
              />
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <AlertPanel items={data.recent_alerts} />
          <InvestigationPanel items={data.recent_investigations} />
          <TopThreatActorsPanel items={data.top_threat_actors} />
          <IndicatorPanel
            title="Recently seen indicators"
            viewAllHref="/indicators"
            items={data.recent_indicators}
            emptyText="No indicators yet."
          />
          <IndicatorPanel
            title="Top malicious indicators"
            viewAllHref="/indicators?verdict=malicious"
            items={data.top_malicious_indicators}
            emptyText="Nothing judged malicious yet."
          />
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Your access</CardTitle>
              <CardDescription>
                Signed in as <span className="font-medium text-foreground">{auth.user.email}</span>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-2 text-sm">
                Role
                <Badge tone="brand" data-testid="access-role">
                  {humanize(auth.profile.role)}
                </Badge>
              </div>
              <dl className="space-y-2">
                {access.map(([resource, actions]) => (
                  <div
                    key={resource}
                    className="flex flex-wrap items-baseline justify-between gap-x-3 text-sm"
                  >
                    <dt className="text-muted">
                      {RESOURCE_LABELS[resource] ?? humanize(resource)}
                    </dt>
                    <dd className="font-medium">
                      {actions.map((action) => action.replaceAll("_", " ")).join(", ")}
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="text-xs text-muted">
                Roles in ArcRadar: {ROLE_NAMES.join(", ")}. What you can do is enforced by the
                server and the database, not just by this page.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Where data comes from</CardTitle>
              <CardDescription>
                Every record carries a provenance label. Demo and local data are never presented as
                live intelligence.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="grid gap-4 sm:grid-cols-3">
                {(["demo", "local", "external"] as const).map((origin) => (
                  <li key={origin} className="space-y-1.5">
                    <OriginBadge origin={origin} />
                    <p className="text-sm text-muted">{ORIGIN_DESCRIPTIONS[origin]}</p>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
