import type { LookupContext, ProviderInfo } from "@/lib/intel/types";
import type { ExploitStatus, Indicator, Row, Severity, Vulnerability } from "@/types/domain";

export type AffectedProduct = Pick<
  Row<"vulnerability_affected_products">,
  "id" | "vendor" | "product" | "affected_versions" | "fixed_version"
>;

/** Everything the detail page shows about one CVE. */
export type VulnerabilityDetail = Vulnerability & {
  affected_products: AffectedProduct[];
  /** The indicator that tracks this CVE in the workspace, if there is one. */
  indicator: Pick<Indicator, "id" | "verdict" | "severity" | "status" | "origin"> | null;
};

export type SeverityCount = { severity: Severity; total: number; exploited: number };

export type VulnerabilityStats = {
  total: number;
  /** Records known to be exploited in the wild. */
  exploited: number;
  /** Every severity, most severe first, including those with no records. */
  by_severity: SeverityCount[];
};

/** A CVE as a provider describes it: the columns that come from outside plus the affected products. */
export type VulnerabilityRecord = {
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_version: "2.0" | "3.0" | "3.1" | "4.0" | null;
  severity: Severity;
  exploit_status: ExploitStatus;
  remediation: string | null;
  reference_urls: string[];
  published_at: string | null;
  modified_at: string | null;
  affected_products: {
    vendor: string;
    product: string;
    affected_versions: string | null;
    fixed_version: string | null;
  }[];
};

/**
 * A source of vulnerability data (the counterpart of `IntelProvider` for CVEs). It returns `null`
 * when it has no record and throws a `ProviderError` when it could not answer.
 */
export interface VulnerabilityProvider {
  readonly info: ProviderInfo;
  lookupCve(cveId: string, context: LookupContext): Promise<VulnerabilityRecord | null>;
}
