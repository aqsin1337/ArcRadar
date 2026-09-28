"use client";

import { Sparkles, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { apiFetch } from "@/lib/api/client";
import { cn } from "@/lib/cn";
import { createChecklistItemSchema } from "@/lib/investigations/schema";
import type { ChecklistItem } from "@/lib/investigations/types";
import { fieldErrorsFromZod } from "@/lib/validation/form";

/**
 * The investigation's checklist: an AI suggestion becomes trackable rows here (the original
 * suggestion stays a separate, immutable AI analysis); an analyst can also add, check off or remove
 * an item by hand.
 *
 * The checkbox keeps its own local list state and flips optimistically on click: a controlled
 * checkbox whose `checked` prop only updates once an async request resolves gets silently reverted by
 * React's own re-render before the click is ever visible (the same bug class found three times in
 * Phase 7's admin controls) — every mutation here updates `items` from what the server actually saved,
 * not by waiting on a full page refresh.
 */
export function ChecklistPanel({
  investigationId,
  items: initialItems,
  canWrite,
  canUseAi,
  aiReady,
}: {
  investigationId: string;
  items: ChecklistItem[];
  canWrite: boolean;
  canUseAi: boolean;
  aiReady: boolean;
}) {
  const [items, setItems] = useState(initialItems);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const base = `/api/investigations/${investigationId}/checklist`;

  async function add() {
    const parsed = createChecklistItemSchema.safeParse({ text: draft });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    setPending("add");
    setError(null);
    const result = await apiFetch<ChecklistItem[]>(base, { body: parsed.data });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setItems(result.data);
    setDraft("");
  }

  async function toggle(item: ChecklistItem) {
    setPending(item.id);
    setError(null);
    const optimistic = !item.done;
    setItems((current) => current.map((i) => (i.id === item.id ? { ...i, done: optimistic } : i)));
    const result = await apiFetch<ChecklistItem[]>(`${base}/${item.id}`, {
      method: "PATCH",
      body: { done: optimistic },
    });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      setItems((current) => current.map((i) => (i.id === item.id ? { ...i, done: item.done } : i)));
      return;
    }
    setItems(result.data);
  }

  async function remove(item: ChecklistItem) {
    setPending(`remove-${item.id}`);
    setError(null);
    const result = await apiFetch<ChecklistItem[]>(`${base}/${item.id}`, { method: "DELETE" });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setItems(result.data);
  }

  async function generate() {
    setPending("generate");
    setError(null);
    const result = await apiFetch(`/api/investigations/${investigationId}/ai`, {
      body: { kind: "investigation_checklist" },
    });
    if (!result.ok) {
      setPending(null);
      setError(result.message);
      return;
    }
    const refreshed = await apiFetch<ChecklistItem[]>(base);
    setPending(null);
    if (refreshed.ok) setItems(refreshed.data);
  }

  const done = items.filter((item) => item.done).length;

  return (
    <div className="space-y-4" data-testid="checklist-panel">
      {error && <Alert tone="error">{error}</Alert>}

      {canUseAi && aiReady && (
        <Button
          type="button"
          variant="secondary"
          size="sm"
          loading={pending === "generate"}
          disabled={pending !== null}
          onClick={generate}
        >
          <Sparkles aria-hidden className="size-4" />
          {items.length > 0 ? "Re-generate with AI" : "Generate with AI"}
        </Button>
      )}
      {canUseAi && !aiReady && (
        <p className="text-sm text-muted">
          No AI provider is configured. Ask an administrator to set one up on the{" "}
          <Link href="/integrations" className="underline underline-offset-2">
            Integrations
          </Link>{" "}
          page.
        </p>
      )}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No checklist items yet.</p>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-muted">
            {done} of {items.length} done
          </p>
          <ul className="space-y-2" aria-label="Checklist">
            {items.map((item) => (
              <li key={item.id} className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={item.done}
                  disabled={!canWrite || pending !== null}
                  onChange={() => toggle(item)}
                  aria-label={item.text}
                  className="mt-0.5 size-4 shrink-0 rounded border-input-border"
                />
                <span className={cn("flex-1 break-words", item.done && "text-muted line-through")}>
                  {item.text}
                </span>
                {item.source === "ai" && (
                  <Badge tone="violet" dashed className="shrink-0">
                    AI
                  </Badge>
                )}
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`Remove "${item.text}"`}
                    disabled={pending !== null}
                    className="shrink-0 rounded-md p-1 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
                    onClick={() => remove(item)}
                  >
                    <Trash2 aria-hidden className="size-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {canWrite && (
        <div className="flex flex-wrap items-end gap-2">
          <TextField
            id="new-checklist-item"
            label="Add an item"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            maxLength={500}
            error={errors.text}
            className="min-w-48 flex-1"
          />
          <Button type="button" loading={pending === "add"} disabled={!draft.trim()} onClick={add}>
            Add
          </Button>
        </div>
      )}
    </div>
  );
}
