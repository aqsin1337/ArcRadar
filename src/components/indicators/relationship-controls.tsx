"use client";

import { X } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { EntityPicker } from "@/components/ui/entity-picker";
import { SelectField } from "@/components/ui/select";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import {
  INDICATOR_TYPE_SHORT_LABELS,
  RELATIONSHIP_TYPES,
  RELATIONSHIP_VERBS,
} from "@/lib/indicators/constants";
import type { IndicatorType, RelationshipType } from "@/types/domain";

type IndicatorHit = { id: string; type: IndicatorType; value: string };

/** Remove one relationship (analysts and administrators). */
export function RemoveRelationshipButton({
  indicatorId,
  relationshipId,
  label,
}: {
  indicatorId: string;
  relationshipId: string;
  /** What the button does, for assistive technology, for example "Remove the link to example.com". */
  label: string;
}) {
  const { pending, error, run } = useAction();
  return (
    <>
      <button
        type="button"
        aria-label={label}
        title={label}
        disabled={pending !== null}
        onClick={() =>
          run("remove", () =>
            apiFetch(`/api/indicators/${indicatorId}/relationships/${relationshipId}`, {
              method: "DELETE",
            }),
          )
        }
        className="rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
      >
        <X aria-hidden className="size-4" />
      </button>
      {error && (
        <span role="alert" className="basis-full text-xs font-medium text-tone-red-fg">
          {error}
        </span>
      )}
    </>
  );
}

/**
 * Relate this indicator to another one: choose how, then search for the other indicator and pick it.
 * The relationship is recorded as "this indicator <how> the other one".
 */
export function AddRelationshipForm({
  indicatorId,
  related,
}: {
  indicatorId: string;
  /** Ids already related in one direction or the other (left out of the results). */
  related: string[];
}) {
  const { pending, error, run } = useAction();
  const [relationship, setRelationship] = useState<RelationshipType>("related_to");

  return (
    <div className="space-y-3 border-t border-border pt-4">
      {error && <Alert tone="error">{error}</Alert>}
      <div className="grid gap-3 sm:grid-cols-[13rem_minmax(0,1fr)]">
        <SelectField
          id="relationship-kind"
          label="This indicator…"
          value={relationship}
          onChange={(event) => setRelationship(event.target.value as RelationshipType)}
          options={RELATIONSHIP_TYPES.map((value) => ({
            value,
            label: RELATIONSHIP_VERBS[value],
          }))}
        />
        <EntityPicker<IndicatorHit>
          id="relationship-target"
          label="…this other indicator"
          placeholder="Search indicators by value, description or tag"
          disabled={pending !== null}
          exclude={[indicatorId, ...related]}
          search={async (text, signal) => {
            const result = await apiFetch<{ items: IndicatorHit[] }>(
              `/api/indicators?q=${encodeURIComponent(text)}&page_size=8`,
              { signal },
            );
            return result.ok ? result.data.items : null;
          }}
          renderItem={(item) => (
            <span className="flex flex-wrap items-center gap-2">
              <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[item.type]}</Badge>
              <span className="font-mono text-[13px] [overflow-wrap:anywhere]">{item.value}</span>
            </span>
          )}
          onPick={(item) =>
            run("add", () =>
              apiFetch(`/api/indicators/${indicatorId}/relationships`, {
                body: { target_id: item.id, relationship },
              }),
            )
          }
        />
      </div>
    </div>
  );
}
