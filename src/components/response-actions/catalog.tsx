"use client";

import { Trash2 } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TextField } from "@/components/ui/input";
import { TextAreaField } from "@/components/ui/textarea";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { createResponseActionSchema } from "@/lib/response-actions/schema";
import type { ResponseAction } from "@/lib/response-actions/types";
import { fieldErrorsFromZod } from "@/lib/validation/form";

/** The response-action catalog: a small, reusable playbook an analyst curates, or an AI "suggest
 * response actions" analysis on an alert seeds automatically. */
export function ResponseActionsCatalog({
  actions,
  canWrite,
}: {
  actions: ResponseAction[];
  canWrite: boolean;
}) {
  const { pending, error, run } = useAction();
  const [form, setForm] = useState({ title: "", description: "", category: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});

  async function add() {
    const parsed = createResponseActionSchema.safeParse(form);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    if (await run("add", () => apiFetch("/api/response-actions", { body: parsed.data }))) {
      setForm({ title: "", description: "", category: "" });
    }
  }

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}

      {canWrite && (
        <Card>
          <CardHeader>
            <CardTitle>New action</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <TextField
              id="ra-title"
              label="Title"
              value={form.title}
              onChange={(event) =>
                setForm((current) => ({ ...current, title: event.target.value }))
              }
              maxLength={200}
              error={errors.title}
            />
            <TextField
              id="ra-category"
              label="Category (optional)"
              hint="For example containment, eradication or communication."
              value={form.category}
              onChange={(event) =>
                setForm((current) => ({ ...current, category: event.target.value }))
              }
              maxLength={50}
              error={errors.category}
            />
            <TextAreaField
              id="ra-description"
              label="Description (optional)"
              value={form.description}
              onChange={(event) =>
                setForm((current) => ({ ...current, description: event.target.value }))
              }
              maxLength={2000}
              rows={2}
              error={errors.description}
            />
            <Button type="button" loading={pending === "add"} onClick={add}>
              Add action
            </Button>
          </CardContent>
        </Card>
      )}

      {actions.length === 0 ? (
        <p className="text-sm text-muted">No response actions in the catalog yet.</p>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2">
          {actions.map((action) => (
            <li key={action.id}>
              <Card>
                <CardHeader className="flex-row items-start justify-between gap-2 space-y-0">
                  <CardTitle className="text-base">{action.title}</CardTitle>
                  {canWrite && (
                    <button
                      type="button"
                      aria-label={`Delete ${action.title}`}
                      disabled={pending !== null}
                      className="shrink-0 rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
                      onClick={() =>
                        run(action.id, () =>
                          apiFetch(`/api/response-actions/${action.id}`, { method: "DELETE" }),
                        )
                      }
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </button>
                  )}
                </CardHeader>
                <CardContent className="space-y-2">
                  {action.category && <Badge tone="slate">{action.category}</Badge>}
                  {action.description ? (
                    <p className="text-sm break-words text-muted">{action.description}</p>
                  ) : (
                    <p className="text-sm text-muted">No description.</p>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
