import { ArrowLeft, Plus } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DetailRow as Row, TimeText as Time } from "@/components/ui/detail-list";
import {
  CvssBadge,
  ExploitStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { ProvenanceNotice } from "@/components/ui/provenance-notice";
import { AccessDenied } from "@/components/ui/states";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { ImportCveButton } from "@/components/vulnerabilities/import-button";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { isCveId } from "@/lib/vulnerabilities/schema";
import { getVulnerability, getVulnerabilityProvider } from "@/lib/vulnerabilities/service";
import type { VulnerabilityDetail } from "@/lib/vulnerabilities/types";

const isHttpUrl = (value: string) => /^https?:\/\//i.test(value);

export default async function VulnerabilityPage({ params }: PageProps<"/vulnerabilities/[cve]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("vulnerabilities:read")) return <AccessDenied />;

  const { cve } = await params;
  if (!isCveId(cve)) notFound();

  let vulnerability: VulnerabilityDetail | null = null;
  try {
    vulnerability = await getVulnerability(auth.supabase, cve);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!vulnerability) notFound();

  const provider = getVulnerabilityProvider();
  const canRefresh =
    vulnerability.origin === "external" &&
    provider !== null &&
    auth.permissions.has("vulnerabilities:write");
  const canTrack = auth.permissions.has("indicators:write");

  return (
    <>
      <title>{`${vulnerability.cve_id} · Vulnerabilities · ArcRadar`}</title>

      <Link
        href="/vulnerabilities"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All vulnerabilities
      </Link>

      <div className="mb-6 min-w-0 space-y-2">
        <h1
          className="font-mono text-xl font-semibold break-all sm:text-2xl"
          data-testid="vulnerability-id"
        >
          {vulnerability.cve_id}
        </h1>
        <p className="max-w-3xl text-base text-muted [overflow-wrap:anywhere]">
          {vulnerability.title}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={vulnerability.severity} />
          <CvssBadge score={vulnerability.cvss_score} severity={vulnerability.severity} />
          <ExploitStatusBadge status={vulnerability.exploit_status} />
          <OriginBadge origin={vulnerability.origin} />
        </div>
      </div>

      <ProvenanceNotice
        origin={vulnerability.origin}
        externalText="Imported from an external provider. Refresh it to pick up later changes."
        className="mb-6"
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerability.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {vulnerability.description}
                </p>
              ) : (
                <p className="text-sm text-muted">No description.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Affected products</CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerability.affected_products.length === 0 ? (
                <p className="text-sm text-muted">No affected products are recorded.</p>
              ) : (
                <Table caption="Affected products">
                  <THead>
                    <tr>
                      <Th>Vendor</Th>
                      <Th>Product</Th>
                      <Th>Affected versions</Th>
                      <Th>Fixed in</Th>
                    </tr>
                  </THead>
                  <TBody>
                    {vulnerability.affected_products.map((product) => (
                      <Tr key={product.id}>
                        <Td>{product.vendor}</Td>
                        <Td>{product.product}</Td>
                        <Td className="text-muted">{product.affected_versions ?? "—"}</Td>
                        <Td className="text-muted">{product.fixed_version ?? "—"}</Td>
                      </Tr>
                    ))}
                  </TBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Remediation</CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerability.remediation ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {vulnerability.remediation}
                </p>
              ) : (
                <p className="text-sm text-muted">No remediation guidance is recorded.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>References</CardTitle>
            </CardHeader>
            <CardContent>
              {vulnerability.reference_urls.length === 0 ? (
                <p className="text-sm text-muted">No references.</p>
              ) : (
                <ul className="space-y-1.5 text-sm">
                  {vulnerability.reference_urls.map((url) => (
                    <li key={url} className="[overflow-wrap:anywhere]">
                      {isHttpUrl(url) ? (
                        <a
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                        >
                          {url}
                        </a>
                      ) : (
                        // Only web links become links: a stored "javascript:" value is shown as text.
                        <span className="text-muted">{url}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Severity">
                  <SeverityBadge severity={vulnerability.severity} />
                </Row>
                <Row label="CVSS score">
                  <CvssBadge score={vulnerability.cvss_score} severity={vulnerability.severity} />
                </Row>
                <Row label="CVSS version">{vulnerability.cvss_version ?? "—"}</Row>
                <Row label="CVSS vector">
                  {vulnerability.cvss_vector ? (
                    <span className="font-mono text-xs [overflow-wrap:anywhere]">
                      {vulnerability.cvss_vector}
                    </span>
                  ) : (
                    "—"
                  )}
                </Row>
                <Row label="Exploit status">
                  <ExploitStatusBadge status={vulnerability.exploit_status} />
                </Row>
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>In your workspace</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {vulnerability.indicator ? (
                <>
                  <dl className="divide-y divide-border">
                    <Row label="Verdict">
                      <VerdictBadge verdict={vulnerability.indicator.verdict} />
                    </Row>
                    <Row label="Severity">
                      <SeverityBadge severity={vulnerability.indicator.severity} />
                    </Row>
                  </dl>
                  <Link
                    href={`/indicators/${vulnerability.indicator.id}`}
                    className={buttonClasses({ variant: "secondary", className: "w-full" })}
                  >
                    Open indicator
                  </Link>
                </>
              ) : (
                <>
                  <p className="text-sm text-muted">This CVE is not tracked as an indicator.</p>
                  {canTrack ? (
                    <Link
                      href={`/indicators/new?type=cve&value=${encodeURIComponent(vulnerability.cve_id)}`}
                      className={buttonClasses({ className: "w-full" })}
                    >
                      <Plus aria-hidden className="size-4" />
                      Track as indicator
                    </Link>
                  ) : (
                    <p className="text-sm text-muted">Analysts and administrators can track it.</p>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Published">
                  {vulnerability.published_at ? <Time iso={vulnerability.published_at} /> : "—"}
                </Row>
                <Row label="Modified">
                  {vulnerability.modified_at ? <Time iso={vulnerability.modified_at} /> : "—"}
                </Row>
                <Row label="Added here">
                  <Time iso={vulnerability.created_at} />
                </Row>
                <Row label="Updated here">
                  <Time iso={vulnerability.updated_at} />
                </Row>
              </dl>
            </CardContent>
          </Card>

          {canRefresh && provider && (
            <ImportCveButton
              cveId={vulnerability.cve_id}
              label={`Refresh from ${provider.info.name}`}
              variant="secondary"
            />
          )}
        </div>
      </div>
    </>
  );
}
