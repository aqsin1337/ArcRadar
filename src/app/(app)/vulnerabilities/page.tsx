import { Bug, SearchX } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Pagination } from "@/components/ui/pagination";
import { AccessDenied, EmptyState } from "@/components/ui/states";
import { ImportCveButton } from "@/components/vulnerabilities/import-button";
import { SeverityStats } from "@/components/vulnerabilities/severity-stats";
import { VulnerabilityFilters } from "@/components/vulnerabilities/vulnerability-filters";
import { VulnerabilityTable } from "@/components/vulnerabilities/vulnerability-table";
import { getPageAuthContext } from "@/lib/auth/session";
import { isCveId, parseVulnerabilityListParams } from "@/lib/vulnerabilities/schema";
import {
  resolveVulnerabilityProvider,
  getVulnerabilityStats,
  listVulnerabilities,
} from "@/lib/vulnerabilities/service";
import { hasActiveVulnerabilityFilters, vulnerabilityListHref } from "@/lib/vulnerabilities/url";

export const metadata: Metadata = { title: "Vulnerabilities" };

function noMatchDescription(cve: string | null, providerName: string | null, canImport: boolean) {
  if (!cve) return "Try fewer words, a different spelling, or remove a filter.";
  if (!providerName) return `${cve} is not in your database.`;
  return canImport
    ? `${cve} is not in your database. You can fetch it from ${providerName}.`
    : `${cve} is not in your database. An administrator can import it from ${providerName}.`;
}

export default async function VulnerabilitiesPage({ searchParams }: PageProps<"/vulnerabilities">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("vulnerabilities:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseVulnerabilityListParams(await searchParams);
  const [result, stats] = await Promise.all([
    listVulnerabilities(auth.supabase, query),
    getVulnerabilityStats(auth.supabase),
  ]);
  const { items, pagination } = result;
  const filtered = hasActiveVulnerabilityFilters(query);

  // Past the last page (a stale link): offer the final page instead of an error.
  const beyondEnd = items.length === 0 && pagination.total > 0;

  // A CVE id that is not in the database can be fetched from the connected provider (administrators).
  const searchedCve = query.q && isCveId(query.q) ? query.q.toUpperCase() : null;
  const provider = await resolveVulnerabilityProvider();
  const canImport = auth.permissions.has("vulnerabilities:write");

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Known vulnerabilities (CVEs) with their severity, CVSS score, exploit status and affected products. Every record shows where it came from."
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <SeverityStats stats={stats} state={query} />
        <VulnerabilityFilters state={query} />

        <div aria-live="polite" className="text-sm text-muted">
          {filtered
            ? `${pagination.total} ${pagination.total === 1 ? "vulnerability matches" : "vulnerabilities match"}`
            : `${pagination.total} ${pagination.total === 1 ? "vulnerability" : "vulnerabilities"}`}
        </div>

        {beyondEnd ? (
          <EmptyState
            icon={SearchX}
            title="That page is past the end"
            description={`There are ${pagination.total_pages} pages of results.`}
            action={
              <Link
                href={vulnerabilityListHref(query, { page: pagination.total_pages })}
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
              title="No vulnerabilities match"
              description={noMatchDescription(searchedCve, provider?.info.name ?? null, canImport)}
              action={
                <>
                  {searchedCve && provider && canImport && (
                    <ImportCveButton
                      cveId={searchedCve}
                      label={`Import ${searchedCve} from ${provider.info.name}`}
                    />
                  )}
                  <Link href="/vulnerabilities" className={buttonClasses({ variant: "secondary" })}>
                    Clear search and filters
                  </Link>
                </>
              }
            />
          ) : (
            <EmptyState
              icon={Bug}
              title="No vulnerabilities yet"
              description="Vulnerability records will appear here once they are added or imported."
            />
          )
        ) : (
          <>
            <VulnerabilityTable items={items} state={query} />
            <Pagination
              page={pagination.page}
              totalPages={pagination.total_pages}
              total={pagination.total}
              pageSize={pagination.page_size}
              noun="vulnerabilities"
              hrefForPage={(page) => vulnerabilityListHref(query, { page })}
            />
          </>
        )}
      </div>
    </>
  );
}
