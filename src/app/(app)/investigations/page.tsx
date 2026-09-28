import { FolderSearch, Plus, SearchX } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { InvestigationFilters } from "@/components/investigations/investigation-filters";
import { InvestigationStatsTiles } from "@/components/investigations/investigation-stats";
import { InvestigationTable } from "@/components/investigations/investigation-table";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Pagination } from "@/components/ui/pagination";
import { AccessDenied, EmptyState } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { listTagOptions } from "@/lib/indicators/service";
import { parseInvestigationListParams } from "@/lib/investigations/schema";
import { getInvestigationStats, listInvestigations } from "@/lib/investigations/service";
import { hasActiveInvestigationFilters, investigationListHref } from "@/lib/investigations/url";
import { findTeamMembers } from "@/lib/team/repository";

export const metadata: Metadata = { title: "Investigations" };

export default async function InvestigationsPage({ searchParams }: PageProps<"/investigations">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("investigations:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseInvestigationListParams(await searchParams);
  const [result, stats, tags, people] = await Promise.all([
    listInvestigations(auth, query),
    getInvestigationStats(auth.supabase),
    listTagOptions(auth.supabase),
    findTeamMembers(auth.supabase, "investigations:write"),
  ]);
  const { items, pagination } = result;
  const filtered = hasActiveInvestigationFilters(query);
  const canWrite = auth.permissions.has("investigations:write");
  const beyondEnd = items.length === 0 && pagination.total > 0;

  const newInvestigation = canWrite && (
    <Link href="/investigations/new" className={buttonClasses()}>
      <Plus aria-hidden className="size-4" />
      New investigation
    </Link>
  );

  return (
    <>
      <PageHeader
        title="Investigations"
        description="Cases your team is working: the indicators and alerts involved, notes, evidence references and a timeline. Every investigation shows where it came from."
        actions={newInvestigation}
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <InvestigationStatsTiles stats={stats} state={query} />
        <InvestigationFilters state={query} tags={tags.map((tag) => tag.name)} people={people} />

        <div aria-live="polite" className="text-sm text-muted">
          {filtered
            ? `${pagination.total} ${pagination.total === 1 ? "investigation matches" : "investigations match"}`
            : `${pagination.total} ${pagination.total === 1 ? "investigation" : "investigations"}`}
        </div>

        {beyondEnd ? (
          <EmptyState
            icon={SearchX}
            title="That page is past the end"
            description={`There are ${pagination.total_pages} pages of results.`}
            action={
              <Link
                href={investigationListHref(query, { page: pagination.total_pages })}
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
              title="No investigations match"
              description="Try fewer words, a different spelling, or remove a filter."
              action={
                <Link href="/investigations" className={buttonClasses({ variant: "secondary" })}>
                  Clear search and filters
                </Link>
              }
            />
          ) : (
            <EmptyState
              icon={FolderSearch}
              title="No investigations yet"
              description={
                canWrite
                  ? "Open one when an alert or an indicator needs a closer look."
                  : "Nothing is being investigated right now."
              }
              action={newInvestigation || undefined}
            />
          )
        ) : (
          <>
            <InvestigationTable items={items} state={query} />
            <Pagination
              page={pagination.page}
              totalPages={pagination.total_pages}
              total={pagination.total}
              pageSize={pagination.page_size}
              noun="investigations"
              hrefForPage={(page) => investigationListHref(query, { page })}
            />
          </>
        )}
      </div>
    </>
  );
}
