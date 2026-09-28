import type { Alert, AlertStatus } from "@/types/domain";

/**
 * The alert lifecycle. An alert starts `new`; an analyst acknowledges it, investigates it and closes
 * it as `resolved` or `false_positive`; a closed alert can be reopened (it goes back to
 * `investigating`, never to `new`). This is a small state machine, kept free of I/O so it can be
 * tested and used by the UI to offer only the actions that make sense.
 */
export const ALERT_TRANSITIONS: Readonly<Record<AlertStatus, readonly AlertStatus[]>> = {
  new: ["acknowledged", "investigating", "resolved", "false_positive"],
  acknowledged: ["investigating", "resolved", "false_positive"],
  investigating: ["resolved", "false_positive"],
  resolved: ["investigating"],
  false_positive: ["investigating"],
};

export const isClosed = (status: AlertStatus) =>
  status === "resolved" || status === "false_positive";

export function canTransition(from: AlertStatus, to: AlertStatus): boolean {
  return ALERT_TRANSITIONS[from].includes(to);
}

type StatusFields = Pick<Alert, "status" | "acknowledged_at" | "resolved_at" | "assigned_to">;

/**
 * The columns to write for a move to `next`. The database requires `resolved_at` to be set exactly
 * when the alert is closed, so both timestamps are worked out here in one place:
 * - `acknowledged_at` is set when the alert first leaves `new` and is kept afterwards;
 * - `resolved_at` is set when it is closed and cleared when it is reopened;
 * - an unassigned alert that an analyst takes out of `new` is assigned to them.
 */
export function buildStatusPatch(
  current: StatusFields,
  next: AlertStatus,
  now: Date,
  actorId: string,
): Pick<Alert, "status" | "acknowledged_at" | "resolved_at"> & { assigned_to?: string } {
  const iso = now.toISOString();
  return {
    status: next,
    acknowledged_at: current.acknowledged_at ?? iso,
    resolved_at: isClosed(next) ? iso : null,
    ...(current.status === "new" && current.assigned_to === null ? { assigned_to: actorId } : {}),
  };
}
