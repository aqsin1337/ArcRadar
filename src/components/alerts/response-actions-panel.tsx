"use client";

import Link from "next/link";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { formatRelative, personLabel } from "@/lib/format";
import {
  RESPONSE_ACTION_STATUS_LABELS,
  RESPONSE_ACTION_TRANSITIONS,
} from "@/lib/response-actions/constants";
import type {
  ResponseAction,
  ResponseActionLogEntry,
  ResponseActionStatus,
} from "@/lib/response-actions/types";

const STATUS_TONES: Record<ResponseActionStatus, Tone> = {
  recommended: "amber",
  acknowledged: "blue",
  completed: "green",
  skipped: "slate",
};

/**
 * Governed response actions for this alert: recommended (by AI or an analyst), then acknowledged and
 * completed or skipped — never executed automatically, never moved backwards. Anyone who can read the
 * alert sees this history; only `alerts:write` can recommend one or move it forward.
 */
export function ResponseActionsPanel({
  alertId,
  entries,
  catalog,
  canWrite,
  now,
}: {
  alertId: string;
  entries: ResponseActionLogEntry[];
  catalog: ResponseAction[];
  canWrite: boolean;
  now: Date;
}) {
  const { pending, error, run } = useAction();
  const [selectedAction, setSelectedAction] = useState("");
  const base = `/api/alerts/${alertId}/response-actions`;

  async function attach() {
    if (!selectedAction) return;
    if (await run("attach", () => apiFetch(base, { body: { action_id: selectedAction } }))) {
      setSelectedAction("");
    }
  }

  async function move(entry: ResponseActionLogEntry, status: ResponseActionStatus) {
    await run(entry.id, () =>
      apiFetch(`${base}/${entry.id}`, { method: "PATCH", body: { status } }),
    );
  }

  return (
    <div className="space-y-4" data-testid="response-actions-panel">
      {error && <Alert tone="error">{error}</Alert>}

      {entries.length === 0 ? (
        <p className="text-sm text-muted">No response actions recommended yet.</p>
      ) : (
        <ul className="space-y-3">
          {entries.map((entry) => {
            const nextSteps = RESPONSE_ACTION_TRANSITIONS[entry.status];
            return (
              <li key={entry.id} className="space-y-2 rounded-lg border border-border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{entry.action_title}</span>
                  <Badge tone={STATUS_TONES[entry.status]}>
                    {RESPONSE_ACTION_STATUS_LABELS[entry.status]}
                  </Badge>
                  {entry.source === "ai" && (
                    <Badge tone="violet" dashed>
                      AI
                    </Badge>
                  )}
                </div>
                {entry.notes && (
                  <p className="text-sm whitespace-pre-wrap text-muted">{entry.notes}</p>
                )}
                <p className="text-xs text-muted">
                  {entry.performed_by_name && entry.performed_at
                    ? `${personLabel({ display_name: entry.performed_by_name })} · ${formatRelative(entry.performed_at, now)}`
                    : `Recommended ${formatRelative(entry.created_at, now)}`}
                </p>
                {canWrite && nextSteps.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {nextSteps.map((step) => (
                      <Button
                        key={step}
                        type="button"
                        size="sm"
                        variant={step === "completed" ? "primary" : "secondary"}
                        loading={pending === entry.id}
                        disabled={pending !== null}
                        onClick={() => move(entry, step)}
                      >
                        {RESPONSE_ACTION_STATUS_LABELS[step]}
                      </Button>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {canWrite &&
        (catalog.length > 0 ? (
          <div className="flex flex-wrap items-end gap-2">
            <label className="block space-y-1">
              <span className="text-xs font-medium text-muted">Recommend an action</span>
              <Select
                value={selectedAction}
                onChange={(event) => setSelectedAction(event.target.value)}
                className="h-9 w-64"
              >
                <option value="">Choose a catalog action…</option>
                {catalog.map((action) => (
                  <option key={action.id} value={action.id}>
                    {action.title}
                  </option>
                ))}
              </Select>
            </label>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              loading={pending === "attach"}
              disabled={!selectedAction}
              onClick={attach}
            >
              Recommend
            </Button>
          </div>
        ) : (
          <p className="text-xs text-muted">
            No response actions exist in the catalog yet.{" "}
            <Link href="/response-actions" className="underline underline-offset-2">
              Add one
            </Link>
            .
          </p>
        ))}
    </div>
  );
}
