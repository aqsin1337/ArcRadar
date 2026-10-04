import type {
  AlertStatus,
  DataOrigin,
  ExploitStatus,
  IndicatorStatus,
  InvestigationStatus,
  Priority,
  Severity,
  Verdict,
} from "@/types/domain";
import { INDICATOR_STATUS_LABELS } from "@/lib/indicators/constants";
import { EXPLOIT_STATUS_LABELS } from "@/lib/vulnerabilities/constants";
import { DATA_ORIGIN_LABELS } from "@/types/domain";
import { Badge, type Tone } from "./badge";

/** "false_positive" -> "False positive". */
export function humanize(value: string): string {
  const text = value.replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const SEVERITY_TONES: Record<Severity, Tone> = {
  info: "blue",
  low: "green",
  medium: "amber",
  high: "orange",
  critical: "red",
};

export const VERDICT_TONES: Record<Verdict, Tone> = {
  unknown: "slate",
  benign: "green",
  suspicious: "amber",
  malicious: "red",
};

const ALERT_STATUS_TONES: Record<AlertStatus, Tone> = {
  new: "blue",
  acknowledged: "amber",
  investigating: "violet",
  resolved: "green",
  false_positive: "slate",
};

const INVESTIGATION_STATUS_TONES: Record<InvestigationStatus, Tone> = {
  open: "blue",
  investigating: "violet",
  contained: "amber",
  resolved: "green",
  closed: "slate",
};

const INDICATOR_STATUS_TONES: Record<IndicatorStatus, Tone> = {
  active: "green",
  inactive: "slate",
  expired: "slate",
  whitelisted: "blue",
  under_review: "amber",
};

const EXPLOIT_STATUS_TONES: Record<ExploitStatus, Tone> = {
  unknown: "slate",
  none: "slate",
  poc_available: "amber",
  exploited_in_wild: "red",
};

export function ExploitStatusBadge({ status }: { status: ExploitStatus }) {
  return <Badge tone={EXPLOIT_STATUS_TONES[status]}>{EXPLOIT_STATUS_LABELS[status]}</Badge>;
}

/** A CVSS base score in the tone of its severity, or "Not scored". The number carries the meaning. */
export function CvssBadge({ score, severity }: { score: number | null; severity: Severity }) {
  if (score === null) return <Badge tone="slate">Not scored</Badge>;
  return (
    <Badge tone={SEVERITY_TONES[severity]} className="tabular-nums">
      CVSS {score.toFixed(1)}
    </Badge>
  );
}

export function IndicatorStatusBadge({ status }: { status: IndicatorStatus }) {
  return <Badge tone={INDICATOR_STATUS_TONES[status]}>{INDICATOR_STATUS_LABELS[status]}</Badge>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={SEVERITY_TONES[severity]} dot>
      {humanize(severity)}
    </Badge>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <Badge tone={VERDICT_TONES[verdict]}>{humanize(verdict)}</Badge>;
}

const PRIORITY_TONES: Record<Priority, Tone> = {
  low: "green",
  medium: "amber",
  high: "orange",
  critical: "red",
};

export function PriorityBadge({ priority }: { priority: Priority }) {
  return (
    <Badge tone={PRIORITY_TONES[priority]} dot>
      {humanize(priority)}
    </Badge>
  );
}

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <Badge tone={ALERT_STATUS_TONES[status]}>{humanize(status)}</Badge>;
}

export function InvestigationStatusBadge({ status }: { status: InvestigationStatus }) {
  return <Badge tone={INVESTIGATION_STATUS_TONES[status]}>{humanize(status)}</Badge>;
}

const ORIGIN_DESCRIPTIONS: Record<DataOrigin, string> = {
  demo: "Sample data for demonstration. Not live intelligence.",
  local: "Entered by a user of this workspace. Not verified by an external provider.",
  external: "Returned by a connected external provider or sensor.",
};

/**
 * Provenance label. Demo and local records must never be presented as live intelligence, so demo
 * gets a dashed violet outline that is unmistakable next to every other badge.
 */
export function OriginBadge({ origin }: { origin: DataOrigin }) {
  const tone: Tone = origin === "demo" ? "violet" : origin === "external" ? "brand" : "slate";
  return (
    <Badge tone={tone} dashed={origin === "demo"} title={ORIGIN_DESCRIPTIONS[origin]}>
      {DATA_ORIGIN_LABELS[origin]}
    </Badge>
  );
}

export { ORIGIN_DESCRIPTIONS };
