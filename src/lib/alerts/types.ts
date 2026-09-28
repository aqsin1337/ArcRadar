import type {
  Alert,
  AlertStatus,
  IndicatorType,
  Priority,
  Row,
  Severity,
  Verdict,
  InvestigationStatus,
} from "@/types/domain";

/** One other alert linked to this one as a duplicate (same fingerprint, within the dedup window). */
export type AlertDuplicate = {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  created_at: string;
};

export type AlertIndicator = { id: string; type: IndicatorType; value: string };
export type AlertAssignee = { id: string; display_name: string | null };

/** A row of the alert list: the record plus its indicator, the machine it came from and who has it. */
export type AlertListItem = Alert & {
  indicator: AlertIndicator | null;
  assignee: AlertAssignee | null;
  asset: { id: string; name: string } | null;
};

/** An ATT&CK technique a sensor tagged the alert with; `name` is null when the workspace does not know it. */
export type AlertTechnique = { id: string; name: string | null };

export type AlertDetail = AlertListItem & {
  indicator: (AlertIndicator & { verdict: Verdict; severity: Severity }) | null;
  asset: { id: string; name: string; ip_address: string | null; os: string | null } | null;
  techniques: AlertTechnique[];
  event: Pick<
    Row<"events">,
    "id" | "title" | "event_type" | "severity" | "source" | "occurred_at" | "payload"
  > | null;
  /** The detection rule that last raised this alert's severity, if any (`alerts.matched_rule_id`). */
  matched_rule: { id: number; name: string } | null;
  /** Set only when this alert is itself a duplicate (`alerts.duplicate_of`). */
  primary_alert: { id: string; title: string; severity: Severity; status: AlertStatus } | null;
  /** Other alerts linked to this one as duplicates; empty unless this is a primary with some. */
  duplicates: AlertDuplicate[];
  investigations: {
    id: string;
    title: string;
    status: InvestigationStatus;
    priority: Priority;
    added_at: string;
  }[];
  created_by_name: string | null;
};

export type AlertStatusCount = { status: AlertStatus; total: number; unassigned: number };

export type AlertStats = {
  total: number;
  /** Alerts nobody has picked up, in any status. */
  unassigned: number;
  /** Every status in lifecycle order, including those with no alerts. */
  by_status: AlertStatusCount[];
};
