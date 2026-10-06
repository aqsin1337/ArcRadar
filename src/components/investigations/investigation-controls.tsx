"use client";

import { Pencil } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { TagInput } from "@/components/ui/tag-input";
import { TextAreaField } from "@/components/ui/textarea";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { personWithRole } from "@/lib/format";
import {
  INVESTIGATION_STATUSES,
  INVESTIGATION_STATUS_LABELS,
  PRIORITIES,
  PRIORITY_LABELS,
} from "@/lib/investigations/constants";
import { updateInvestigationSchema } from "@/lib/investigations/schema";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import type { InvestigationStatus, Priority } from "@/types/domain";

type Person = { id: string; display_name: string | null; role?: string };

type Props = {
  investigation: {
    id: string;
    title: string;
    description: string | null;
    status: InvestigationStatus;
    priority: Priority;
    analyst_id: string | null;
    tags: string[];
  };
  people: Person[];
  tagOptions: string[];
};

/**
 * What an analyst changes about an investigation: status, priority and analyst (each saved as soon as
 * it is picked, and each leaves a line in the history), and the title, description and tags (saved
 * with the button). The server checks everything again.
 */
export function InvestigationControls({ investigation, people, tagOptions }: Props) {
  const { pending, error, run, clearError } = useAction();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState({
    title: investigation.title,
    description: investigation.description ?? "",
    tags: investigation.tags,
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const patch = (key: string, body: Record<string, unknown>) =>
    run(key, () => apiFetch(`/api/investigations/${investigation.id}`, { method: "PATCH", body }));

  async function saveDetails() {
    const parsed = updateInvestigationSchema.safeParse(draft);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    const saved = await patch("details", parsed.data);
    if (saved) setEditing(false);
  }

  return (
    <div className="space-y-4" data-testid="investigation-controls">
      {error && (
        <Alert tone="error">
          {error}{" "}
          <button type="button" className="font-semibold underline" onClick={clearError}>
            Dismiss
          </button>
        </Alert>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <label className="block space-y-1">
          <span className="text-xs font-medium text-muted">Status</span>
          <Select
            value={investigation.status}
            disabled={pending !== null}
            onChange={(event) => patch("status", { status: event.target.value })}
            className="h-9"
          >
            {INVESTIGATION_STATUSES.map((status) => (
              <option key={status} value={status}>
                {INVESTIGATION_STATUS_LABELS[status]}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1">
          <span className="text-xs font-medium text-muted">Priority</span>
          <Select
            value={investigation.priority}
            disabled={pending !== null}
            onChange={(event) => patch("priority", { priority: event.target.value })}
            className="h-9"
          >
            {PRIORITIES.map((priority) => (
              <option key={priority} value={priority}>
                {PRIORITY_LABELS[priority]}
              </option>
            ))}
          </Select>
        </label>
        <label className="block space-y-1">
          <span className="text-xs font-medium text-muted">Analyst</span>
          <Select
            value={investigation.analyst_id ?? ""}
            disabled={pending !== null}
            onChange={(event) => patch("analyst", { analyst_id: event.target.value || null })}
            className="h-9"
          >
            <option value="">Unassigned</option>
            {people.map((person) => (
              <option key={person.id} value={person.id}>
                {personWithRole(person)}
              </option>
            ))}
          </Select>
        </label>
      </div>

      {editing ? (
        <div className="space-y-4 rounded-lg border border-border p-4">
          <TextField
            id="edit-title"
            label="Title"
            required
            value={draft.title}
            onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))}
            maxLength={300}
            error={errors.title}
          />
          <TextAreaField
            id="edit-description"
            label="Description"
            value={draft.description}
            onChange={(event) =>
              setDraft((current) => ({ ...current, description: event.target.value }))
            }
            maxLength={10000}
            rows={5}
            error={errors.description}
          />
          <TagInput
            id="edit-tags"
            label="Tags"
            value={draft.tags}
            onChange={(tags) => setDraft((current) => ({ ...current, tags }))}
            suggestions={tagOptions}
            error={errors.tags}
          />
          <div className="flex items-center gap-2">
            <Button type="button" loading={pending === "details"} onClick={saveDetails}>
              Save changes
            </Button>
            <Button
              type="button"
              variant="ghost"
              disabled={pending !== null}
              onClick={() => {
                setEditing(false);
                setErrors({});
                setDraft({
                  title: investigation.title,
                  description: investigation.description ?? "",
                  tags: investigation.tags,
                });
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button type="button" variant="secondary" size="sm" onClick={() => setEditing(true)}>
          <Pencil aria-hidden className="size-4" />
          Edit title, description and tags
        </Button>
      )}
    </div>
  );
}
