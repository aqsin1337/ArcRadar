import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findIndicatorByKey } from "@/lib/indicators/repository";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import type { Severity, Vulnerability } from "@/types/domain";
import { SEVERITIES_BY_RANK } from "./constants";
import type { VulnerabilityListQuery } from "./schema";
import type { VulnerabilityDetail, VulnerabilityRecord, VulnerabilityStats } from "./types";

/*
 * Reads use the caller's own client, so row level security decides what is visible. The one write,
 * recording a CVE fetched from an external provider, goes through import_external_vulnerability()
 * with the service role, after the service has authorized the caller.
 */

/** One page of vulnerabilities matching the text search and filters, plus the total match count. */
export async function findVulnerabilities(
  supabase: AuthClient,
  query: VulnerabilityListQuery,
): Promise<{ rows: Vulnerability[]; total: number }> {
  const { from, to } = toRange(query);

  // search_vulnerabilities() answers the text question; everything else is ordinary PostgREST.
  const build = () => {
    let request = supabase.rpc("search_vulnerabilities", { p_query: query.q }, { count: "exact" });
    if (query.severity) request = request.eq("severity", query.severity);
    if (query.exploit_status) request = request.eq("exploit_status", query.exploit_status);
    if (query.origin) request = request.eq("origin", query.origin);
    if (query.min_cvss !== undefined) request = request.gte("cvss_score", query.min_cvss);
    return request;
  };

  // Records without a score or a date always sort last, whichever way the list is ordered.
  const { data, error, count } = await build()
    .order(query.sort, { ascending: query.order === "asc", nullsFirst: false })
    .order("id", { ascending: true }) // a stable tie-breaker keeps pages from overlapping
    .range(from, to);

  if (error?.code === "PGRST103") {
    // A page past the last row (a stale link, a hand-typed page number): learn the total, return no rows.
    const first = await build().range(0, 0);
    if (first.error) throw toApiError(first.error);
    return { rows: [], total: first.count ?? 0 };
  }
  if (error) throw toApiError(error);

  return { rows: data ?? [], total: count ?? 0 };
}

/** One CVE with its affected products and the workspace indicator that tracks it. */
export async function findVulnerabilityDetail(
  supabase: AuthClient,
  cveId: string,
): Promise<VulnerabilityDetail | null> {
  const { data, error } = await supabase
    .from("vulnerabilities")
    .select(
      "*, vulnerability_affected_products(id, vendor, product, affected_versions, fixed_version)",
    )
    .eq("cve_id", cveId)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const tracked = await findIndicatorByKey(supabase, "cve", cveId);
  const { vulnerability_affected_products, ...row } = data;
  return {
    ...row,
    affected_products: [...vulnerability_affected_products].sort(
      (a, b) => a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product),
    ),
    indicator: tracked
      ? {
          id: tracked.id,
          verdict: tracked.verdict,
          severity: tracked.severity,
          status: tracked.status,
          origin: tracked.origin,
        }
      : null,
  };
}

/** How many records the caller can see per severity, and how many of them are exploited in the wild. */
export async function findSeverityStats(supabase: AuthClient): Promise<VulnerabilityStats> {
  const { data, error } = await supabase.rpc("vulnerability_severity_counts");
  if (error) throw toApiError(error);

  const counts = new Map<Severity, { total: number; exploited: number }>(
    data.map((row) => [
      row.severity,
      { total: Number(row.total), exploited: Number(row.exploited) },
    ]),
  );
  const by_severity = SEVERITIES_BY_RANK.map((severity) => ({
    severity,
    total: counts.get(severity)?.total ?? 0,
    exploited: counts.get(severity)?.exploited ?? 0,
  }));
  return {
    total: by_severity.reduce((sum, row) => sum + row.total, 0),
    exploited: by_severity.reduce((sum, row) => sum + row.exploited, 0),
    by_severity,
  };
}

/** The origin of an existing record with this CVE id, or null. */
export async function findVulnerabilityOrigin(
  supabase: AuthClient,
  cveId: string,
): Promise<Vulnerability["origin"] | null> {
  const { data, error } = await supabase
    .from("vulnerabilities")
    .select("origin")
    .eq("cve_id", cveId)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data?.origin ?? null;
}

/**
 * Records (or refreshes) a CVE from an external provider. Service role only: call it after
 * authorizing the user. A demo or local record with the same id is never overwritten (409).
 */
export async function importExternalVulnerability(record: VulnerabilityRecord): Promise<void> {
  const { error } = await createAdminClient().rpc("import_external_vulnerability", {
    p: record as unknown as Json,
  });
  if (!error) return;
  if (error.code === "23505") {
    throw apiErrors.conflict(
      "This CVE already exists as demo or local data, so it was not replaced.",
    );
  }
  if (error.code === "22023" || error.code === "23514") {
    throw apiErrors.validation({
      issues: [{ path: "cve_id", message: "The provider's record could not be stored." }],
    });
  }
  throw toApiError(error);
}
