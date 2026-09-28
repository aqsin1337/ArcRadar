"use client";

import { X } from "lucide-react";
import Link from "next/link";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  AlertStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { EntityPicker } from "@/components/ui/entity-picker";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { TimeText } from "@/components/ui/detail-list";
import { INDICATOR_TYPE_SHORT_LABELS } from "@/lib/indicators/constants";
import type { LinkedAlert, LinkedIndicator } from "@/lib/investigations/types";
import type { AlertStatus, IndicatorType, Severity } from "@/types/domain";

type IndicatorHit = { id: string; type: IndicatorType; value: string };
type AlertHit = { id: string; title: string; severity: Severity; status: AlertStatus };

async function searchList<T>(path: string, signal: AbortSignal): Promise<T[] | null> {
  const result = await apiFetch<{ items: T[] }>(path, { signal });
  return result.ok ? result.data.items : null;
}

function RemoveButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className="rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
    >
      <X aria-hidden className="size-4" />
    </button>
  );
}

/** The indicators attached to an investigation, with a search box to attach more (analysts). */
export function LinkedIndicators({
  investigationId,
  items,
  canWrite,
}: {
  investigationId: string;
  items: LinkedIndicator[];
  canWrite: boolean;
}) {
  const { pending, error, run } = useAction();
  const base = `/api/investigations/${investigationId}/indicators`;

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No indicators are attached yet.</p>
      ) : (
        <ul className="divide-y divide-border" aria-label="Attached indicators">
          {items.map((item) => (
            <li
              key={item.id}
              className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2 first:pt-0 last:pb-0"
            >
              <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[item.type]}</Badge>
              <Link
                href={`/indicators/${item.id}`}
                className="font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
              >
                {item.value}
              </Link>
              <span className="ml-auto inline-flex items-center gap-1.5">
                <VerdictBadge verdict={item.verdict} />
                <OriginBadge origin={item.origin} />
                {canWrite && (
                  <RemoveButton
                    label={`Detach ${item.value}`}
                    disabled={pending !== null}
                    onClick={() =>
                      run(item.id, () => apiFetch(`${base}/${item.id}`, { method: "DELETE" }))
                    }
                  />
                )}
              </span>
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <EntityPicker<IndicatorHit>
          id="attach-indicator"
          label="Attach an indicator"
          placeholder="Search indicators by value, description or tag"
          disabled={pending !== null}
          exclude={items.map((item) => item.id)}
          search={(text, signal) =>
            searchList<IndicatorHit>(
              `/api/indicators?q=${encodeURIComponent(text)}&page_size=8`,
              signal,
            )
          }
          renderItem={(item) => (
            <span className="flex flex-wrap items-center gap-2">
              <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[item.type]}</Badge>
              <span className="font-mono text-[13px] [overflow-wrap:anywhere]">{item.value}</span>
            </span>
          )}
          onPick={(item) =>
            run("attach", () => apiFetch(base, { body: { indicator_id: item.id } }))
          }
        />
      )}
    </div>
  );
}

/** The alerts attached to an investigation, with a search box to attach more (analysts). */
export function LinkedAlerts({
  investigationId,
  items,
  canWrite,
}: {
  investigationId: string;
  items: LinkedAlert[];
  canWrite: boolean;
}) {
  const { pending, error, run } = useAction();
  const base = `/api/investigations/${investigationId}/alerts`;

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No alerts are attached yet.</p>
      ) : (
        <ul className="divide-y divide-border" aria-label="Attached alerts">
          {items.map((item) => (
            <li
              key={item.id}
              className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2 first:pt-0 last:pb-0"
            >
              <SeverityBadge severity={item.severity} />
              <Link
                href={`/alerts/${item.id}`}
                className="text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline"
              >
                {item.title}
              </Link>
              <span className="ml-auto inline-flex items-center gap-1.5">
                <AlertStatusBadge status={item.status} />
                <span className="hidden text-xs text-muted sm:inline">
                  <TimeText iso={item.added_at} />
                </span>
                {canWrite && (
                  <RemoveButton
                    label={`Detach ${item.title}`}
                    disabled={pending !== null}
                    onClick={() =>
                      run(item.id, () => apiFetch(`${base}/${item.id}`, { method: "DELETE" }))
                    }
                  />
                )}
              </span>
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <EntityPicker<AlertHit>
          id="attach-alert"
          label="Attach an alert"
          placeholder="Search alerts by title, source or indicator"
          disabled={pending !== null}
          exclude={items.map((item) => item.id)}
          search={(text, signal) =>
            searchList<AlertHit>(`/api/alerts?q=${encodeURIComponent(text)}&page_size=8`, signal)
          }
          renderItem={(item) => (
            <span className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={item.severity} />
              <span className="[overflow-wrap:anywhere]">{item.title}</span>
              <span className="ml-auto">
                <AlertStatusBadge status={item.status} />
              </span>
            </span>
          )}
          onPick={(item) => run("attach", () => apiFetch(base, { body: { alert_id: item.id } }))}
        />
      )}
    </div>
  );
}
