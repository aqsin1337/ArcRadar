"use client";

import { Pencil, Trash2 } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TimeText } from "@/components/ui/detail-list";
import { Textarea } from "@/components/ui/textarea";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { personLabel } from "@/lib/format";
import type { InvestigationNote } from "@/lib/investigations/types";

/**
 * The analysts' notes on an investigation (the status history lives in the timeline). Anyone who may
 * write can add a note; only its author can edit it, and an administrator can also remove it.
 */
export function NotesPanel({
  investigationId,
  notes,
  currentUserId,
  canWrite,
  canModerate,
}: {
  investigationId: string;
  notes: InvestigationNote[];
  currentUserId: string;
  canWrite: boolean;
  canModerate: boolean;
}) {
  const { pending, error, run } = useAction();
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<{ id: string; body: string } | null>(null);
  const base = `/api/investigations/${investigationId}/notes`;
  const ordinary = notes.filter((note) => note.kind === "note");

  async function add() {
    if (!draft.trim()) return;
    if (await run("add", () => apiFetch(base, { body: { body: draft } }))) setDraft("");
  }

  async function save() {
    if (!editing || !editing.body.trim()) return;
    const saved = await run("save", () =>
      apiFetch(`${base}/${editing.id}`, { method: "PATCH", body: { body: editing.body } }),
    );
    if (saved) setEditing(null);
  }

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}

      {ordinary.length === 0 ? (
        <p className="text-sm text-muted">No notes yet.</p>
      ) : (
        <ul className="space-y-4" aria-label="Notes">
          {ordinary.map((note) => {
            const own = note.author_id === currentUserId;
            return (
              <li key={note.id} className="space-y-1.5 rounded-lg border border-border p-3">
                <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted">
                  <span className="font-medium text-foreground">
                    {personLabel({ display_name: note.author_name })}
                  </span>
                  <TimeText iso={note.created_at} />
                  {note.updated_at !== note.created_at && <span>(edited)</span>}
                  {canWrite && (own || canModerate) && editing?.id !== note.id && (
                    <span className="ml-auto inline-flex items-center gap-1">
                      {own && (
                        <button
                          type="button"
                          aria-label="Edit this note"
                          className="rounded-md p-1.5 hover:bg-surface-2 hover:text-foreground"
                          onClick={() => setEditing({ id: note.id, body: note.body })}
                        >
                          <Pencil aria-hidden className="size-4" />
                        </button>
                      )}
                      <button
                        type="button"
                        aria-label="Delete this note"
                        disabled={pending !== null}
                        className="rounded-md p-1.5 hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
                        onClick={() =>
                          run(`delete-${note.id}`, () =>
                            apiFetch(`${base}/${note.id}`, { method: "DELETE" }),
                          )
                        }
                      >
                        <Trash2 aria-hidden className="size-4" />
                      </button>
                    </span>
                  )}
                </div>
                {editing?.id === note.id ? (
                  <div className="space-y-2">
                    <Textarea
                      aria-label="Edit note"
                      value={editing.body}
                      onChange={(event) => setEditing({ id: note.id, body: event.target.value })}
                      maxLength={10000}
                      rows={4}
                    />
                    <div className="flex gap-2">
                      <Button type="button" size="sm" loading={pending === "save"} onClick={save}>
                        Save note
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        onClick={() => setEditing(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                    {note.body}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {canWrite && (
        <div className="space-y-2">
          <label htmlFor="new-note" className="block text-sm font-medium">
            Add a note
          </label>
          <Textarea
            id="new-note"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            maxLength={10000}
            rows={3}
            placeholder="What you found, decided or still need to check."
          />
          <Button type="button" loading={pending === "add"} disabled={!draft.trim()} onClick={add}>
            Add note
          </Button>
        </div>
      )}
    </div>
  );
}
