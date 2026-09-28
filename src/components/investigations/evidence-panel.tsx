"use client";

import { Trash2 } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TimeText } from "@/components/ui/detail-list";
import { TextField } from "@/components/ui/input";
import { TextAreaField } from "@/components/ui/textarea";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { personLabel } from "@/lib/format";
import { evidenceSchema } from "@/lib/investigations/schema";
import type { InvestigationEvidence } from "@/lib/investigations/types";
import { fieldErrorsFromZod } from "@/lib/validation/form";

const isWebLink = (value: string) => /^https?:\/\//i.test(value);

/**
 * Evidence references: where something can be found (a link, a file hash, a ticket number, a path),
 * not an uploaded file. Only web links become links; anything else is shown as text.
 */
export function EvidencePanel({
  investigationId,
  items,
  canWrite,
}: {
  investigationId: string;
  items: InvestigationEvidence[];
  canWrite: boolean;
}) {
  const { pending, error, run } = useAction();
  const [form, setForm] = useState({ title: "", location: "", description: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const base = `/api/investigations/${investigationId}/evidence`;

  async function add() {
    const parsed = evidenceSchema.safeParse(form);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    if (await run("add", () => apiFetch(base, { body: parsed.data }))) {
      setForm({ title: "", location: "", description: "" });
    }
  }

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No evidence has been referenced yet.</p>
      ) : (
        <ul className="divide-y divide-border" aria-label="Evidence">
          {items.map((item) => (
            <li key={item.id} className="space-y-1 py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">{item.title}</span>
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`Remove ${item.title}`}
                    title={`Remove ${item.title}`}
                    disabled={pending !== null}
                    className="ml-auto rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
                    onClick={() =>
                      run(item.id, () => apiFetch(`${base}/${item.id}`, { method: "DELETE" }))
                    }
                  >
                    <Trash2 aria-hidden className="size-4" />
                  </button>
                )}
              </div>
              {isWebLink(item.location) ? (
                <a
                  href={item.location}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
                >
                  {item.location}
                </a>
              ) : (
                <p className="font-mono text-[13px] [overflow-wrap:anywhere]">{item.location}</p>
              )}
              {item.description && (
                <p className="text-sm whitespace-pre-wrap text-muted [overflow-wrap:anywhere]">
                  {item.description}
                </p>
              )}
              <p className="text-xs text-muted">
                Added by {personLabel({ display_name: item.added_by_name })} ·{" "}
                <TimeText iso={item.created_at} />
              </p>
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <fieldset className="space-y-3 rounded-lg border border-border p-3">
          <legend className="px-1 text-sm font-medium">Add evidence</legend>
          <TextField
            id="evidence-title"
            label="Title"
            value={form.title}
            onChange={(event) => setForm((current) => ({ ...current, title: event.target.value }))}
            maxLength={200}
            error={errors.title}
          />
          <TextField
            id="evidence-location"
            label="Location"
            value={form.location}
            onChange={(event) =>
              setForm((current) => ({ ...current, location: event.target.value }))
            }
            maxLength={2048}
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
            error={errors.location}
            hint="A link, a file hash, a ticket number or a path."
          />
          <TextAreaField
            id="evidence-description"
            label="Description (optional)"
            value={form.description}
            onChange={(event) =>
              setForm((current) => ({ ...current, description: event.target.value }))
            }
            maxLength={5000}
            rows={2}
            error={errors.description}
          />
          <Button type="button" loading={pending === "add"} onClick={add}>
            Add evidence
          </Button>
        </fieldset>
      )}
    </div>
  );
}
