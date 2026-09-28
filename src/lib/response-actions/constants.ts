import type { ResponseActionStatus } from "./types";

/** Not a Postgres enum (just `text` + a check constraint, like `investigation_notes.kind`): there is
 * no generated `Constants.public.Enums` entry for it, so the list is written out here. */
export const RESPONSE_ACTION_STATUSES = [
  "recommended",
  "acknowledged",
  "completed",
  "skipped",
] as const;

export const RESPONSE_ACTION_STATUS_LABELS: Record<ResponseActionStatus, string> = {
  recommended: "Recommended",
  acknowledged: "Acknowledged",
  completed: "Completed",
  skipped: "Skipped",
};

/**
 * A response action is recommended (by AI or an analyst), then an analyst acknowledges it, and
 * completes or skips it, with an optional note. It never moves backwards: this is a governance trail,
 * not a to-do list to un-check. Modelled after `src/lib/alerts/workflow.ts`.
 */
export const RESPONSE_ACTION_TRANSITIONS: Readonly<
  Record<ResponseActionStatus, readonly ResponseActionStatus[]>
> = {
  recommended: ["acknowledged", "completed", "skipped"],
  acknowledged: ["completed", "skipped"],
  completed: [],
  skipped: [],
};

export function canTransitionResponseAction(
  from: ResponseActionStatus,
  to: ResponseActionStatus,
): boolean {
  return RESPONSE_ACTION_TRANSITIONS[from].includes(to);
}
