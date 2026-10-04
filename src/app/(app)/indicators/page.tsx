import { Crosshair, Plus, SearchX } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { IndicatorFilters } from "@/components/indicators/indicator-filters";
import { IndicatorTable } from "@/components/indicators/indicator-table";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Pagination } from "@/components/ui/pagination";
import { AccessDenied, EmptyState } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseIndicatorListParams } from "@/lib/indicators/schema";
import { listIndicators, listTagOptions } from "@/lib/indicators/service";
import { hasActiveFilters, indicatorListHref } from "@/lib/indicators/url";

export const metadata: Metadata = { title: "Indicators" };

export default async function IndicatorsPage({ searchParams }: PageProps<"/indicators">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("indicators:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseIndicatorListParams(await searchParams);
  const [result, tags] = await Promise.all([
    listIndicators(auth.supabase, query),
    listTagOptions(auth.supabase),
  ]);
  const { items, pagination } = result;
  const filtered = hasActiveFilters(query);
  const canWrite = auth.permissions.has("indicators:write");

  // Past the last page (for example after deleting the last item of a page): go to the final page.
  const beyondEnd = items.length === 0 && pagination.total > 0;

  return (
    <>
      <PageHeader
        title="Indicators"
        description="Observable indicators of compromise: IP addresses, domains, URLs, file hashes, email addresses and CVEs. Every record shows where it came from."
        actions={
          canWrite && (
            <Link href="/indicators/new" className={buttonClasses()}>
              <Plus aria-hidden className="size-4" />
              New indicator
            </Link>
          )
        }
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <IndicatorFilters state={query} tags={tags.map((tag) => tag.name)} />

        <div aria-live="polite" className="text-sm text-muted">
          {filtered
            ? `${pagination.total} ${pagination.total === 1 ? "indicator matches" : "indicators match"}`
            : `${pagination.total} ${pagination.total === 1 ? "indicator" : "indicators"}`}
        </div>

        {beyondEnd ? (
          <EmptyState
            icon={SearchX}
            title="That page is past the end"
            description={`There are ${pagination.total_pages} pages of results.`}
            action={
              <Link
                href={indicatorListHref(query, { page: pagination.total_pages })}
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
              title="No indicators match"
              description="Try fewer words, a different spelling, or remove a filter."
              action={
                <Link href="/indicators" className={buttonClasses({ variant: "secondary" })}>
                  Clear search and filters
                </Link>
              }
            />
          ) : (
            <EmptyState
              icon={Crosshair}
              title="No indicators yet"
              description={
                canWrite
                  ? "Add the first indicator to start tracking it."
                  : "Nothing has been added yet. An analyst or administrator can add indicators."
              }
              action={
                canWrite && (
                  <Link href="/indicators/new" className={buttonClasses()}>
                    <Plus aria-hidden className="size-4" />
                    New indicator
                  </Link>
                )
              }
            />
          )
        ) : (
          <>
            <IndicatorTable items={items} state={query} />
            <Pagination
              page={pagination.page}
              totalPages={pagination.total_pages}
              total={pagination.total}
              pageSize={pagination.page_size}
              noun="indicators"
              hrefForPage={(page) => indicatorListHref(query, { page })}
            />
          </>
        )}
      </div>
    </>
  );
}
