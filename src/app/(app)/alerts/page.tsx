import { Bell, Plus, SearchX } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { AlertFilters } from "@/components/alerts/alert-filters";
import { AlertStatsTiles } from "@/components/alerts/alert-stats";
import { AlertTable } from "@/components/alerts/alert-table";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Pagination } from "@/components/ui/pagination";
import { AccessDenied, EmptyState } from "@/components/ui/states";
import { parseAlertListParams } from "@/lib/alerts/schema";
import { getAlertStats, listAlertSources, listAlerts } from "@/lib/alerts/service";
import { alertListHref, hasActiveAlertFilters } from "@/lib/alerts/url";
import { getPageAuthContext } from "@/lib/auth/session";
import { findTeamMembers } from "@/lib/team/repository";

export const metadata: Metadata = { title: "Alerts" };

export default async function AlertsPage({ searchParams }: PageProps<"/alerts">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("alerts:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseAlertListParams(await searchParams);
  const [result, stats, sources, people] = await Promise.all([
    listAlerts(auth, query),
    getAlertStats(auth.supabase),
    listAlertSources(auth.supabase),
    findTeamMembers(auth.supabase, "alerts:write"),
  ]);
  const { items, pagination } = result;
  const filtered = hasActiveAlertFilters(query);
  const canWrite = auth.permissions.has("alerts:write");

  // Past the last page (for example after the alerts of the last page were closed): offer the final page.
  const beyondEnd = items.length === 0 && pagination.total > 0;

  const newAlert = canWrite && (
    <Link href="/alerts/new" className={buttonClasses()}>
      <Plus aria-hidden className="size-4" />
      New alert
    </Link>
  );

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections that need a decision. Acknowledge an alert, investigate it, and close it as resolved or a false positive. Every alert shows where it came from."
        actions={newAlert}
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <AlertStatsTiles stats={stats} state={query} />
        <AlertFilters state={query} sources={sources} people={people} />

        <div aria-live="polite" className="text-sm text-muted">
          {filtered
            ? `${pagination.total} ${pagination.total === 1 ? "alert matches" : "alerts match"}`
            : `${pagination.total} ${pagination.total === 1 ? "alert" : "alerts"}`}
        </div>

        {beyondEnd ? (
          <EmptyState
            icon={SearchX}
            title="That page is past the end"
            description={`There are ${pagination.total_pages} pages of results.`}
            action={
              <Link
                href={alertListHref(query, { page: pagination.total_pages })}
                className={buttonClasses()}
              >
                Go to the last page
              </Link>
            }
          />
        ) : items.length === 0 ? (
          filtered ? (
            <EmptyState
              icon={SearchX}
              title="No alerts match"
              description="Try fewer words, a different spelling, or remove a filter."
              action={
                <Link href="/alerts" className={buttonClasses({ variant: "secondary" })}>
                  Clear search and filters
                </Link>
              }
            />
          ) : (
            <EmptyState
              icon={Bell}
              title="No alerts"
              description={
                canWrite
                  ? "Nothing needs attention. Alerts delivered by a sensor appear here, and you can also record one by hand."
                  : "Nothing needs attention right now."
              }
              action={newAlert || undefined}
            />
          )
        ) : (
          <>
            <AlertTable items={items} state={query} />
            <Pagination
              page={pagination.page}
              totalPages={pagination.total_pages}
              total={pagination.total}
              pageSize={pagination.page_size}
              noun="alerts"
              hrefForPage={(page) => alertListHref(query, { page })}
            />
          </>
        )}
      </div>
    </>
  );
}
