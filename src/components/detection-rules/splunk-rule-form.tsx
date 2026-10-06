"use client";

import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import type { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input, TextField } from "@/components/ui/input";
import { Select, SelectField } from "@/components/ui/select";
import { TextAreaField } from "@/components/ui/textarea";
import { SIEM_RULE_SEVERITIES } from "@/lib/siem-rules/constants";
import {
  SPLUNK_CONDITION_OPS,
  SPLUNK_FIELD_SUGGESTIONS,
  SPLUNK_SCHEDULES,
  SPLUNK_SOURCETYPE_SUGGESTIONS,
  splunkDialect,
  type SplunkConditionOp,
  type SplunkSchedule,
  type SplunkSpec,
} from "@/lib/siem-rules/dialects/splunk";
import { fieldOptions, sourcesFor, type FieldCatalog } from "@/lib/siem-rules/catalog";
import { createSiemRuleSchema, updateSiemRuleSchema } from "@/lib/siem-rules/schema";
import type { SiemRule } from "@/lib/siem-rules/types";
import { formatRelative } from "@/lib/format";
import { WAZUH_CONDITION_OP_LABELS } from "@/lib/wazuh-rules/constants";

/** What every SIEM's form component receives: the rule being edited (if any) and how to report back. */
export type SiemRuleFormProps = {
  rule: SiemRule | null;
  pending: boolean;
  submitLabel: string;
  serverErrors: Record<string, string>;
  /** The fields Splunk reported (empty until it has). */
  catalog: FieldCatalog;
  onSubmit: (payload: Record<string, unknown>) => void;
  onCancel: () => void;
};

type Condition = { field: string; op: SplunkConditionOp; value: string };

type FormState = {
  rule_key: string;
  name: string;
  description: string;
  severity: string;
  mitre: string;
  index: string;
  sourcetype: string;
  schedule: SplunkSchedule;
  conditions: Condition[];
  repeat: boolean;
  count: string;
  window: string;
  by: string;
};

/** First message per full path (`spec.conditions.0.value`), the same paths the API reports. */
function errorsByPath(error: z.ZodError): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const issue of error.issues) {
    const key = issue.path.join(".");
    if (!(key in errors)) errors[key] = issue.message;
  }
  return errors;
}

const emptyCondition = (): Condition => ({ field: "EventCode", op: "equals", value: "" });

const listFrom = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);

function initialState(rule: SiemRule | null): FormState {
  if (!rule) {
    return {
      rule_key: "",
      name: "",
      description: "",
      severity: "medium",
      mitre: "",
      index: "main",
      sourcetype: "WinEventLog:Security",
      schedule: "every_5_minutes",
      conditions: [emptyCondition()],
      repeat: false,
      count: "5",
      window: "5",
      by: "",
    };
  }
  const spec = rule.spec as unknown as SplunkSpec;
  return {
    rule_key: rule.rule_key,
    name: rule.name,
    description: rule.description ?? "",
    severity: rule.severity,
    mitre: rule.mitre_ids.join(", "),
    index: spec.index,
    sourcetype: spec.sourcetype ?? "",
    schedule: spec.schedule,
    conditions: spec.conditions.map((condition) => ({ ...condition })),
    repeat: spec.threshold !== null,
    count: String(spec.threshold?.count ?? 5),
    window: String(spec.threshold?.window_minutes ?? 5),
    by: spec.threshold?.by.join(", ") ?? "",
  };
}

/** Errors under `spec.conditions...` are shown together beneath the condition builder. */
const conditionErrors = (errors: Record<string, string>) =>
  Object.entries(errors)
    .filter(([path]) => path === "spec" || path.startsWith("spec.conditions"))
    .map(([, message]) => message);

export function SplunkRuleForm({
  rule,
  pending,
  submitLabel,
  serverErrors,
  catalog,
  onSubmit,
  onCancel,
}: SiemRuleFormProps) {
  const editing = rule !== null;
  const [form, setForm] = useState(() => initialState(rule));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const shown = { ...serverErrors, ...errors };
  const set = (patch: Partial<FormState>) => setForm((current) => ({ ...current, ...patch }));
  const idPrefix = editing ? "sp-edit" : "sp-new";

  // What Splunk really holds for the index and sourcetype typed so far.
  const indexName = form.index.trim();
  const sourcetypeName = form.sourcetype.trim() || null;
  const known = sourcesFor(catalog, indexName, sourcetypeName);
  const options = fieldOptions(catalog, indexName, sourcetypeName);
  const optionByName = new Map(options.map((option) => [option.name, option]));
  const indexNames = [...new Set(catalog.sources.map((source) => source.index))];
  const sourcetypeNames =
    catalog.sources.length > 0
      ? [
          ...new Set(
            catalog.sources
              .filter((source) => source.index === indexName)
              .map((source) => source.sourcetype),
          ),
        ]
      : [...SPLUNK_SOURCETYPE_SUGGESTIONS];
  const reported = catalog.sources
    .map((source) => source.reported_at)
    .sort()
    .at(-1);
  const windowHours = known[0]?.window_hours ?? catalog.sources[0]?.window_hours ?? 24;

  function updateCondition(index: number, patch: Partial<Condition>) {
    set({
      conditions: form.conditions.map((condition, i) =>
        i === index ? { ...condition, ...patch } : condition,
      ),
    });
  }

  function submit() {
    const spec = {
      index: form.index,
      sourcetype: form.sourcetype.trim() === "" ? null : form.sourcetype,
      conditions: form.conditions,
      threshold: form.repeat
        ? {
            count: Number(form.count),
            window_minutes: Number(form.window),
            by: listFrom(form.by),
          }
        : null,
      schedule: form.schedule,
    };
    const base = {
      name: form.name,
      description: form.description,
      severity: form.severity,
      mitre_ids: listFrom(form.mitre),
      spec,
    };
    const payload = editing
      ? base
      : { ...base, ...(form.rule_key.trim() === "" ? {} : { rule_key: form.rule_key.trim() }) };
    const schema = editing
      ? updateSiemRuleSchema(splunkDialect)
      : createSiemRuleSchema(splunkDialect);
    const parsed = schema.safeParse(payload);
    if (!parsed.success) {
      setErrors(errorsByPath(parsed.error));
      return;
    }
    setErrors({});
    onSubmit(payload);
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-[180px_1fr_140px]">
        <TextField
          id={`${idPrefix}-key`}
          label={editing ? "Rule key" : "Rule key (optional)"}
          hint={editing ? undefined : "Empty = next free number"}
          value={form.rule_key}
          onChange={(event) => set({ rule_key: event.target.value })}
          disabled={editing}
          readOnly={editing}
          error={shown.rule_key}
        />
        <TextField
          id={`${idPrefix}-name`}
          label="Name"
          value={form.name}
          onChange={(event) => set({ name: event.target.value })}
          maxLength={200}
          error={shown.name}
        />
        <SelectField
          id={`${idPrefix}-severity`}
          label="Severity"
          value={form.severity}
          onChange={(event) => set({ severity: event.target.value })}
          options={SIEM_RULE_SEVERITIES.map((value) => ({
            value,
            label: value.charAt(0).toUpperCase() + value.slice(1),
          }))}
          error={shown.severity}
        />
      </div>

      <TextAreaField
        id={`${idPrefix}-description`}
        label="Description (optional)"
        value={form.description}
        onChange={(event) => set({ description: event.target.value })}
        maxLength={2000}
        rows={2}
        error={shown.description}
      />

      <p className="text-xs text-muted">
        {reported
          ? `Index, sourcetype and fields below come from what Splunk reported ${formatRelative(reported, new Date())} (a sample of its last ${windowHours} h). You can still type a name that is not listed.`
          : "Splunk has not reported its fields yet, so these are only suggestions. Run the catalog sync on the Splunk host (docs/SPLUNK_INTEGRATION.md) to list the real ones."}
      </p>
      <div className="grid gap-3 sm:grid-cols-[160px_1fr_200px]">
        <div>
          <TextField
            id={`${idPrefix}-index`}
            label="Index"
            list={`${idPrefix}-indexes`}
            value={form.index}
            onChange={(event) => set({ index: event.target.value })}
            error={shown["spec.index"]}
          />
          <datalist id={`${idPrefix}-indexes`}>
            {indexNames.map((item) => (
              <option key={item} value={item} />
            ))}
          </datalist>
        </div>
        <div>
          <TextField
            id={`${idPrefix}-sourcetype`}
            label="Sourcetype (optional)"
            list={`${idPrefix}-sourcetypes`}
            value={form.sourcetype}
            onChange={(event) => set({ sourcetype: event.target.value })}
            error={shown["spec.sourcetype"]}
          />
          <datalist id={`${idPrefix}-sourcetypes`}>
            {sourcetypeNames.map((item) => (
              <option key={item} value={item} />
            ))}
          </datalist>
        </div>
        <SelectField
          id={`${idPrefix}-schedule`}
          label="Runs"
          value={form.schedule}
          onChange={(event) => set({ schedule: event.target.value as SplunkSchedule })}
          options={(Object.keys(SPLUNK_SCHEDULES) as SplunkSchedule[]).map((value) => ({
            value,
            label: SPLUNK_SCHEDULES[value].label,
          }))}
          error={shown["spec.schedule"]}
        />
      </div>

      <div className="space-y-2">
        <p className="text-sm font-medium">Conditions (every one must match)</p>
        <datalist id={`${idPrefix}-fields`}>
          {options.length > 0
            ? options.map((option) => (
                <option
                  key={option.name}
                  value={option.name}
                  label={`${option.percent}%${option.examples.length > 0 ? " · " + option.examples.slice(0, 3).join(", ") : ""}`}
                />
              ))
            : SPLUNK_FIELD_SUGGESTIONS.map((field) => <option key={field} value={field} />)}
        </datalist>
        {form.conditions.map((condition, index) => {
          const option = optionByName.get(condition.field.trim());
          return (
            <div key={index} className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  aria-label={`Condition ${index + 1} field`}
                  list={`${idPrefix}-fields`}
                  value={condition.field}
                  onChange={(event) => updateCondition(index, { field: event.target.value })}
                  className="min-w-44 flex-1"
                />
                <Select
                  aria-label={`Condition ${index + 1} comparison`}
                  value={condition.op}
                  onChange={(event) =>
                    updateCondition(index, { op: event.target.value as SplunkConditionOp })
                  }
                  className="w-auto min-w-36"
                >
                  {SPLUNK_CONDITION_OPS.map((op) => (
                    <option key={op} value={op}>
                      {WAZUH_CONDITION_OP_LABELS[op]}
                    </option>
                  ))}
                </Select>
                <Input
                  aria-label={`Condition ${index + 1} value`}
                  list={`${idPrefix}-values-${index}`}
                  value={condition.value}
                  onChange={(event) => updateCondition(index, { value: event.target.value })}
                  maxLength={200}
                  className="min-w-40 flex-[2]"
                />
                {(form.conditions.length > 1 || form.repeat) && (
                  <button
                    type="button"
                    aria-label={`Remove condition ${index + 1}`}
                    className="shrink-0 rounded-md p-2 text-muted hover:bg-surface-2 hover:text-foreground"
                    onClick={() =>
                      set({ conditions: form.conditions.filter((_, i) => i !== index) })
                    }
                  >
                    <Trash2 aria-hidden className="size-4" />
                  </button>
                )}
              </div>
              <datalist id={`${idPrefix}-values-${index}`}>
                {(option?.examples ?? []).map((value) => (
                  <option key={value} value={value} />
                ))}
              </datalist>
              {condition.field.trim() !== "" && known.length > 0 && (
                <p className={option ? "text-xs text-muted" : "text-xs text-tone-amber-fg"}>
                  {option
                    ? `Seen in ${option.percent}% of events${option.examples.length > 0 ? " · examples: " + option.examples.join(", ") : ""}`
                    : `Not seen in this data in the last ${windowHours} h. Check the spelling, or the sourcetype.`}
                </p>
              )}
            </div>
          );
        })}
        {conditionErrors(shown).map((message, index) => (
          <p key={index} className="text-sm text-tone-red-fg">
            {message}
          </p>
        ))}
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={() => set({ conditions: [...form.conditions, emptyCondition()] })}
        >
          <Plus aria-hidden className="size-4" />
          Add condition
        </Button>
      </div>

      <div className="space-y-2 rounded-lg border border-border p-3">
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={form.repeat}
            onChange={(event) => set({ repeat: event.target.checked })}
            className="size-4 rounded border-input-border"
          />
          Only when it repeats
        </label>
        {form.repeat && (
          <>
            <p className="text-xs text-muted">
              The conditions above describe the single event that is counted. The rule fires when it
              happened this many times inside the window, once per group. Conditions are then
              optional.
            </p>
            <div className="grid gap-3 sm:grid-cols-[140px_180px_1fr]">
              <TextField
                id={`${idPrefix}-count`}
                label="Times"
                inputMode="numeric"
                value={form.count}
                onChange={(event) => set({ count: event.target.value })}
                error={shown["spec.threshold.count"]}
              />
              <TextField
                id={`${idPrefix}-window`}
                label="Within (minutes)"
                inputMode="numeric"
                value={form.window}
                onChange={(event) => set({ window: event.target.value })}
                error={shown["spec.threshold.window_minutes"]}
              />
              <TextField
                id={`${idPrefix}-by`}
                label="Count per (optional)"
                hint="For example Source_Network_Address: counts per source"
                list={`${idPrefix}-fields`}
                value={form.by}
                onChange={(event) => set({ by: event.target.value })}
                error={shown["spec.threshold.by"]}
              />
            </div>
          </>
        )}
      </div>

      <TextField
        id={`${idPrefix}-mitre`}
        label="MITRE ATT&CK techniques (optional)"
        hint="Comma separated, for example T1110, T1078"
        value={form.mitre}
        onChange={(event) => set({ mitre: event.target.value })}
        error={shown.mitre_ids}
      />

      <div className="flex flex-wrap gap-2">
        <Button type="button" loading={pending} onClick={submit}>
          {submitLabel}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
