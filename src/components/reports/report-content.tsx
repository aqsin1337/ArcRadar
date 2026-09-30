import Link from "next/link";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { DistributionBars } from "@/components/ui/distribution-bars";
import { humanize, SEVERITY_TONES, VERDICT_TONES } from "@/components/ui/domain-badges";
import type {
  AlertsReportContent,
  IndicatorsReportContent,
  InvestigationReportContent,
  VulnerabilitiesReportContent,
} from "@/lib/reports/types";
import type { ReportType } from "@/types/domain";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-lg border border-border bg-surface p-3">
      <p className="text-2xl font-semibold tabular-nums">{value}</p>
      <p className="text-xs text-muted">{label}</p>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function IndicatorsView({ content }: { content: IndicatorsReportContent }) {
  return (
    <div className="space-y-6">
      <Stat label="Total indicators" value={content.total} />
      <Section title="By type">
        <DistributionBars
          rows={content.by_type.map((row) => ({ label: humanize(row.type), total: row.total }))}
        />
      </Section>
      <Section title="By verdict">
        <DistributionBars
          rows={content.by_verdict.map((row) => ({
            label: humanize(row.verdict),
            total: row.total,
            tone: VERDICT_TONES[row.verdict],
          }))}
        />
      </Section>
      <Section title="Most recently seen malicious">
        {content.top_malicious.length === 0 ? (
          <p className="text-sm text-muted">None.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {content.top_malicious.map((item) => (
              <li key={item.id}>
                <Link href={`/indicators/${item.id}`} className="text-primary hover:underline">
                  <span className="font-mono">{item.value}</span>
                </Link>{" "}
                <span className="text-muted">
                  ({humanize(item.type)}, {humanize(item.severity)})
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function AlertsView({ content }: { content: AlertsReportContent }) {
  return (
    <div className="space-y-6">
      <Stat label="Total alerts" value={content.total} />
      <Section title="By status">
        <DistributionBars
          rows={content.by_status.map((row) => ({ label: humanize(row.status), total: row.total }))}
        />
      </Section>
      <Section title="By severity">
        <DistributionBars
          rows={content.by_severity.map((row) => ({
            label: humanize(row.severity),
            total: row.total,
            tone: SEVERITY_TONES[row.severity],
          }))}
        />
      </Section>
      <Section title="Still open">
        {content.open.length === 0 ? (
          <p className="text-sm text-muted">None.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {content.open.map((alert) => (
              <li key={alert.id}>
                <Link href={`/alerts/${alert.id}`} className="text-primary hover:underline">
                  {alert.title}
                </Link>{" "}
                <span className="text-muted">
                  ({humanize(alert.severity)}, {humanize(alert.status)})
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function VulnerabilitiesView({ content }: { content: VulnerabilitiesReportContent }) {
  return (
    <div className="space-y-6">
      <Stat label="Total vulnerabilities" value={content.total} />
      <Section title="By severity">
        <DistributionBars
          rows={content.by_severity.map((row) => ({
            label: `${humanize(row.severity)} (${row.exploited} exploited)`,
            total: row.total,
            tone: SEVERITY_TONES[row.severity],
          }))}
        />
      </Section>
      <Section title="Exploited in the wild">
        {content.exploited_in_wild.length === 0 ? (
          <p className="text-sm text-muted">None.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {content.exploited_in_wild.map((cve) => (
              <li key={cve.cve_id}>
                <Link
                  href={`/vulnerabilities/${cve.cve_id}`}
                  className="text-primary hover:underline"
                >
                  {cve.cve_id}
                </Link>{" "}
                <span className="text-muted">
                  {cve.title}
                  {cve.cvss_score !== null && ` — CVSS ${cve.cvss_score.toFixed(1)}`}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function InvestigationView({ content }: { content: InvestigationReportContent }) {
  const { investigation } = content;
  return (
    <div className="space-y-6">
      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-muted">Status</dt>
          <dd>{humanize(investigation.status)}</dd>
        </div>
        <div>
          <dt className="text-muted">Priority</dt>
          <dd>{humanize(investigation.priority)}</dd>
        </div>
        <div>
          <dt className="text-muted">Analyst</dt>
          <dd>{investigation.analyst ?? "Unassigned"}</dd>
        </div>
        <div>
          <dt className="text-muted">Opened</dt>
          <dd>{new Date(investigation.created_at).toISOString().slice(0, 10)}</dd>
        </div>
      </dl>
      <Section title={`Indicators (${content.indicators.length})`}>
        {content.indicators.length === 0 ? (
          <p className="text-sm text-muted">None attached.</p>
        ) : (
          <ul className="flex flex-wrap gap-1.5">
            {content.indicators.map((item) => (
              <li key={item.id}>
                <Badge tone="slate">
                  <span className="font-mono">{item.value}</span>
                </Badge>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title={`Alerts (${content.alerts.length})`}>
        {content.alerts.length === 0 ? (
          <p className="text-sm text-muted">None attached.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {content.alerts.map((alert) => (
              <li key={alert.id}>
                {alert.title} <span className="text-muted">({humanize(alert.status)})</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Notes and history">
        {content.notes.length === 0 ? (
          <p className="text-sm text-muted">None yet.</p>
        ) : (
          <ol className="space-y-3 border-l border-border pl-4">
            {content.notes.map((note, index) => (
              <li key={index}>
                <p className="text-xs text-muted">
                  {note.author ?? "System"} ·{" "}
                  {new Date(note.created_at).toISOString().slice(0, 16).replace("T", " ")} UTC
                </p>
                <p className="text-sm">{note.body}</p>
              </li>
            ))}
          </ol>
        )}
      </Section>
      <Section title={`Evidence (${content.evidence.length})`}>
        {content.evidence.length === 0 ? (
          <p className="text-sm text-muted">None yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {content.evidence.map((item, index) => (
              <li key={index}>
                {item.title} <span className="text-muted">— {item.location}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

/** Renders whichever shape `content` has, keyed by the report's own type. */
export function ReportContent({ type, content }: { type: ReportType; content: object }) {
  switch (type) {
    case "indicators":
      return <IndicatorsView content={content as IndicatorsReportContent} />;
    case "alerts":
      return <AlertsView content={content as AlertsReportContent} />;
    case "vulnerabilities":
      return <VulnerabilitiesView content={content as VulnerabilitiesReportContent} />;
    case "investigation":
      return <InvestigationView content={content as InvestigationReportContent} />;
    case "threat_actor":
      return (
        <p className="text-sm text-muted">This report type was retired and cannot be shown.</p>
      );
  }
}
