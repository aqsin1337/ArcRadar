"use client";

import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, TextField } from "@/components/ui/input";
import { Select, SelectField } from "@/components/ui/select";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import {
  DETECTION_RULE_FIELD_LABELS,
  DETECTION_RULE_FIELD_OPS,
  DETECTION_RULE_FIELDS,
  DETECTION_RULE_OP_LABELS,
} from "@/lib/detection-rules/constants";
import { createDetectionRuleSchema } from "@/lib/detection-rules/schema";
import type { DetectionRule, DetectionRuleCondition } from "@/lib/detection-rules/types";
import { SEVERITIES, SEVERITY_LABELS } from "@/lib/indicators/constants";
import { fieldErrorsFromZod } from "@/lib/validation/form";

const emptyCondition = (): DetectionRuleCondition => ({
  field: "title",
  op: DETECTION_RULE_FIELD_OPS.title[0],
  value: "",
});

const emptyForm = () => ({
  id: "",
  name: "",
  description: "",
  severity: "",
  priority: "",
  conditions: [emptyCondition()],
});

/**
 * The detection-rule catalog: a fixed, closed condition grammar (field/comparison/value), never a
 * filter built from free text -- the database's own detection_rule_matches() is the authority and
 * fails closed on anything this form does not offer. The `enabled` checkbox keeps its own local list
 * state and flips optimistically on click, the same fix this codebase has needed for every controlled
 * checkbox bound to server-refreshed state (Phase 7's admin toggles, Phase 9's checklist).
 */
export function DetectionRulesManager({
  rules,
  canManage,
}: {
  rules: DetectionRule[];
  canManage: boolean;
}) {
  const [items, setItems] = useState(rules);
  const [form, setForm] = useState(emptyForm());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  function updateCondition(index: number, patch: Partial<DetectionRuleCondition>) {
    setForm((current) => ({
      ...current,
      conditions: current.conditions.map((condition, i) =>
        i === index ? { ...condition, ...patch } : condition,
      ),
    }));
  }

  function addCondition() {
    setForm((current) => ({ ...current, conditions: [...current.conditions, emptyCondition()] }));
  }

  function removeCondition(index: number) {
    setForm((current) => ({
      ...current,
      conditions: current.conditions.filter((_, i) => i !== index),
    }));
  }

  async function add() {
    const parsed = createDetectionRuleSchema.safeParse({
      id: Number(form.id),
      name: form.name,
      description: form.description,
      conditions: form.conditions,
      severity: form.severity === "" ? undefined : form.severity,
      priority: form.priority === "" ? undefined : Number(form.priority),
    });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      setFormError(null);
      return;
    }
    setErrors({});
    setFormError(null);
    setPending("add");
    const result = await apiFetch<DetectionRule>("/api/detection-rules", { body: parsed.data });
    setPending(null);
    if (!result.ok) {
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    setItems((current) =>
      [...current, result.data].sort((a, b) => a.priority - b.priority || a.id - b.id),
    );
    setForm(emptyForm());
  }

  async function toggle(rule: DetectionRule) {
    setPending(String(rule.id));
    const enabled = !rule.enabled;
    setItems((current) => current.map((r) => (r.id === rule.id ? { ...r, enabled } : r)));
    const result = await apiFetch<DetectionRule>(`/api/detection-rules/${rule.id}`, {
      method: "PATCH",
      body: { enabled },
    });
    setPending(null);
    if (!result.ok) {
      setFormError(result.message);
      setItems((current) =>
        current.map((r) => (r.id === rule.id ? { ...r, enabled: !enabled } : r)),
      );
      return;
    }
    setItems((current) => current.map((r) => (r.id === rule.id ? result.data : r)));
  }

  async function remove(rule: DetectionRule) {
    setPending(`remove-${rule.id}`);
    setFormError(null);
    const result = await apiFetch(`/api/detection-rules/${rule.id}`, { method: "DELETE" });
    setPending(null);
    if (!result.ok) {
      setFormError(result.message);
      return;
    }
    setItems((current) => current.filter((r) => r.id !== rule.id));
  }

  return (
    <div className="space-y-4">
      {formError && <Alert tone="error">{formError}</Alert>}

      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle>New rule</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-[160px_1fr]">
              <TextField
                id="dr-id"
                label="Rule id"
                hint="100000-999999"
                inputMode="numeric"
                value={form.id}
                onChange={(event) => setForm((current) => ({ ...current, id: event.target.value }))}
                error={errors.id}
              />
              <TextField
                id="dr-name"
                label="Name"
                value={form.name}
                onChange={(event) =>
                  setForm((current) => ({ ...current, name: event.target.value }))
                }
                maxLength={200}
                error={errors.name}
              />
            </div>
            <TextAreaField
              id="dr-description"
              label="Description (optional)"
              value={form.description}
              onChange={(event) =>
                setForm((current) => ({ ...current, description: event.target.value }))
              }
              maxLength={2000}
              rows={2}
              error={errors.description}
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <SelectField
                id="dr-severity"
                label="Raise severity to"
                value={form.severity}
                onChange={(event) =>
                  setForm((current) => ({ ...current, severity: event.target.value }))
                }
                options={SEVERITIES.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
                placeholder="No override, just trace the match"
                error={errors.severity}
              />
              <TextField
                id="dr-priority"
                label="Priority"
                hint="Lower runs first, 1-1000; default 100"
                inputMode="numeric"
                value={form.priority}
                onChange={(event) =>
                  setForm((current) => ({ ...current, priority: event.target.value }))
                }
                error={errors.priority}
              />
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium">Conditions (every one must match)</p>
              {form.conditions.map((condition, index) => (
                <div key={index} className="flex flex-wrap items-center gap-2">
                  <Select
                    aria-label={`Condition ${index + 1} field`}
                    value={condition.field}
                    onChange={(event) => {
                      const field = event.target.value as DetectionRuleCondition["field"];
                      updateCondition(index, { field, op: DETECTION_RULE_FIELD_OPS[field][0] });
                    }}
                    className="w-auto min-w-36"
                  >
                    {DETECTION_RULE_FIELDS.map((field) => (
                      <option key={field} value={field}>
                        {DETECTION_RULE_FIELD_LABELS[field]}
                      </option>
                    ))}
                  </Select>
                  <Select
                    aria-label={`Condition ${index + 1} comparison`}
                    value={condition.op}
                    onChange={(event) =>
                      updateCondition(index, {
                        op: event.target.value as DetectionRuleCondition["op"],
                      })
                    }
                    className="w-auto min-w-28"
                  >
                    {DETECTION_RULE_FIELD_OPS[condition.field].map((op) => (
                      <option key={op} value={op}>
                        {DETECTION_RULE_OP_LABELS[op]}
                      </option>
                    ))}
                  </Select>
                  <Input
                    aria-label={`Condition ${index + 1} value`}
                    value={condition.value}
                    onChange={(event) => updateCondition(index, { value: event.target.value })}
                    maxLength={200}
                    className="min-w-32 flex-1"
                  />
                  {form.conditions.length > 1 && (
                    <button
                      type="button"
                      aria-label={`Remove condition ${index + 1}`}
                      className="shrink-0 rounded-md p-2 text-muted hover:bg-surface-2 hover:text-foreground"
                      onClick={() => removeCondition(index)}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </button>
                  )}
                </div>
              ))}
              {errors.conditions && <p className="text-sm text-tone-red-fg">{errors.conditions}</p>}
              <Button type="button" variant="secondary" size="sm" onClick={addCondition}>
                <Plus aria-hidden className="size-4" />
                Add condition
              </Button>
            </div>

            <Button type="button" loading={pending === "add"} onClick={add}>
              Add rule
            </Button>
          </CardContent>
        </Card>
      )}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No detection rules yet.</p>
      ) : (
        <ul className="space-y-3">
          {items.map((rule) => (
            <li key={rule.id}>
              <Card>
                <CardHeader className="flex-row flex-wrap items-start justify-between gap-2 space-y-0">
                  <div className="space-y-1">
                    <CardTitle className="text-base">
                      {rule.name} <span className="font-mono text-xs text-muted">#{rule.id}</span>
                    </CardTitle>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge tone="slate">Priority {rule.priority}</Badge>
                      {rule.severity && (
                        <Badge tone="amber">Raises to {SEVERITY_LABELS[rule.severity]}</Badge>
                      )}
                    </div>
                  </div>
                  {canManage && (
                    <button
                      type="button"
                      aria-label={`Delete ${rule.name}`}
                      disabled={pending !== null}
                      className="shrink-0 rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50"
                      onClick={() => remove(rule)}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </button>
                  )}
                </CardHeader>
                <CardContent className="space-y-2">
                  {rule.description && (
                    <p className="text-sm break-words text-muted">{rule.description}</p>
                  )}
                  <ul className="flex flex-wrap gap-1.5">
                    {rule.conditions.map((condition, index) => (
                      <li key={index}>
                        <Badge tone="slate">
                          {DETECTION_RULE_FIELD_LABELS[condition.field]}{" "}
                          {DETECTION_RULE_OP_LABELS[condition.op]} &quot;{condition.value}&quot;
                        </Badge>
                      </li>
                    ))}
                  </ul>
                  {canManage ? (
                    <label className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        disabled={pending !== null}
                        onChange={() => toggle(rule)}
                        className="size-4 rounded border-input-border"
                      />
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </label>
                  ) : (
                    <p className="text-xs text-muted">{rule.enabled ? "Enabled" : "Disabled"}</p>
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
