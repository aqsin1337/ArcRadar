"use client";

import { FolderPlus, UserCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, type ButtonVariant } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { apiFetch } from "@/lib/api/client";
import { ASSIGNEE_ME } from "@/lib/alerts/constants";
import { ALERT_TRANSITIONS, isClosed } from "@/lib/alerts/workflow";
import { personLabel } from "@/lib/format";
import type { AlertStatus } from "@/types/domain";

type Person = { id: string; display_name: string | null };

/** What a move to `to` is called on a button, given where the alert is now. */
function actionLabel(
  from: AlertStatus,
  to: AlertStatus,
): { label: string; variant: ButtonVariant } {
  switch (to) {
    case "acknowledged":
      return { label: "Acknowledge", variant: "secondary" };
    case "investigating":
      return isClosed(from)
        ? { label: "Reopen", variant: "secondary" }
        : { label: "Start investigating", variant: "primary" };
    case "resolved":
      return { label: "Resolve", variant: "secondary" };
    case "false_positive":
      return { label: "Mark as false positive", variant: "ghost" };
    default:
      return { label: to, variant: "secondary" };
  }
}

/**
 * The alert workflow on the detail page: the moves the lifecycle allows from the current status, an
 * assignee menu, and (for someone who may open one) starting an investigation from the alert. The
 * server has the last word: a move that is no longer allowed, or an alert someone else just changed,
 * comes back as a message here.
 */
export function AlertActions({
  alert,
  people,
  canInvestigate,
}: {
  alert: {
    id: string;
    title: string;
    status: AlertStatus;
    assigned_to: string | null;
    indicator_id: string | null;
  };
  people: Person[];
  canInvestigate: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function patch(key: string, body: { status?: AlertStatus; assigned_to?: string | null }) {
    if (pending) return;
    setPending(key);
    setError(null);
    const result = await apiFetch(`/api/alerts/${alert.id}`, { method: "PATCH", body });
    setPending(null);
    if (result.ok) router.refresh();
    else setError(result.message);
  }

  async function startInvestigation() {
    if (pending) return;
    setPending("investigate");
    setError(null);
    const result = await apiFetch<{ id: string }>("/api/investigations", {
      body: {
        title: alert.title.slice(0, 300),
        priority: "medium",
        alert_ids: [alert.id],
        ...(alert.indicator_id ? { indicator_ids: [alert.indicator_id] } : {}),
      },
    });
    if (result.ok) {
      router.push(`/investigations/${result.data.id}`);
      router.refresh();
    } else {
      setPending(null);
      setError(result.message);
    }
  }

  return (
    <div className="space-y-4" data-testid="alert-actions">
      {error && <Alert tone="error">{error}</Alert>}

      <div className="flex flex-wrap items-center gap-2">
        {ALERT_TRANSITIONS[alert.status].map((to) => {
          const { label, variant } = actionLabel(alert.status, to);
          return (
            <Button
              key={to}
              type="button"
              variant={variant}
              loading={pending === to}
              disabled={pending !== null}
              onClick={() => patch(to, { status: to })}
            >
              {label}
            </Button>
          );
        })}
        {canInvestigate && (
          <Button
            type="button"
            variant="secondary"
            loading={pending === "investigate"}
            disabled={pending !== null}
            onClick={startInvestigation}
          >
            <FolderPlus aria-hidden className="size-4" />
            Open an investigation
          </Button>
        )}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <label className="block space-y-1">
          <span className="text-xs font-medium text-muted">Assigned to</span>
          <Select
            value={alert.assigned_to ?? ""}
            disabled={pending !== null}
            onChange={(event) => patch("assign", { assigned_to: event.target.value || null })}
            className="h-9 w-56"
          >
            <option value="">Unassigned</option>
            {people.map((person) => (
              <option key={person.id} value={person.id}>
                {personLabel(person)}
              </option>
            ))}
          </Select>
        </label>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={pending !== null}
          onClick={() => patch("assign", { assigned_to: ASSIGNEE_ME })}
        >
          <UserCheck aria-hidden className="size-4" />
          Assign to me
        </Button>
      </div>
    </div>
  );
}
