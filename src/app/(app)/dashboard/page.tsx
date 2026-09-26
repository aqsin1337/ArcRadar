import { Radar } from "lucide-react";
import type { Metadata } from "next";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { humanize, ORIGIN_DESCRIPTIONS, OriginBadge } from "@/components/ui/domain-badges";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { ROLE_NAMES } from "@/types/domain";

export const metadata: Metadata = { title: "Overview" };

// Display names for permission resources whose plain humanized form would read badly.
const RESOURCE_LABELS: Record<string, string> = {
  api_keys: "API keys",
  threat_intel: "Threat intelligence",
  audit: "Audit log",
};

/** "indicators:read", "indicators:write" -> [["indicators", ["read", "write"]]] */
function groupPermissions(permissions: Iterable<string>): [string, string[]][] {
  const groups = new Map<string, string[]>();
  for (const permission of permissions) {
    const [resource, action] = permission.split(":");
    groups.set(resource, [...(groups.get(resource) ?? []), action]);
  }
  return [...groups];
}

export default async function DashboardPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const name = auth.profile.display_name ?? auth.user.email ?? "there";
  const access = groupPermissions(auth.permissions);

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Welcome, ${name}. This is your workspace; modules appear in the sidebar as they are built.`}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Threat overview</CardTitle>
            <CardDescription>Live counts and trends will be shown here.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState
              icon={Radar}
              title="No data to show yet"
              description="Indicators, alerts and vulnerabilities will appear here once those modules are built. Nothing on this page is sample data."
            />
          </CardContent>
        </Card>

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
                  <dt className="text-muted">{RESOURCE_LABELS[resource] ?? humanize(resource)}</dt>
                  <dd className="font-medium">
                    {actions.map((action) => action.replaceAll("_", " ")).join(", ")}
                  </dd>
                </div>
              ))}
            </dl>
            <p className="text-xs text-muted">
              Roles in ArcRadar: {ROLE_NAMES.join(", ")}. What you can do is enforced by the server
              and the database, not just by this page.
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
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
    </>
  );
}
