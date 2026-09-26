"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { SelectField } from "@/components/ui/select";
import { TagInput } from "@/components/ui/tag-input";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import { toDateTimeLocalValue } from "@/lib/format";
import {
  INDICATOR_STATUSES,
  INDICATOR_STATUS_LABELS,
  INDICATOR_TYPES,
  INDICATOR_TYPE_LABELS,
  SEVERITIES,
  SEVERITY_LABELS,
  VERDICTS,
  VERDICT_LABELS,
} from "@/lib/indicators/constants";
import { createIndicatorSchema, updateIndicatorSchema } from "@/lib/indicators/schema";
import type { IndicatorListItem } from "@/lib/indicators/types";
import { VALUE_HINTS, validateIndicatorValue } from "@/lib/indicators/value";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import type { IndicatorStatus, IndicatorType, Severity, Verdict } from "@/types/domain";

type Values = {
  type: IndicatorType;
  value: string;
  severity: Severity;
  verdict: Verdict;
  status: IndicatorStatus;
  confidence: string;
  source: string;
  description: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
};

const DEFAULTS: Values = {
  type: "ipv4",
  value: "",
  severity: "medium",
  verdict: "unknown",
  status: "active",
  confidence: "50",
  source: "manual",
  description: "",
  first_seen: "",
  last_seen: "",
  tags: [],
};

const without = <T,>(record: Record<string, T>, key: string) =>
  Object.fromEntries(Object.entries(record).filter(([name]) => name !== key));

const options = <T extends string>(values: readonly T[], labels: Record<T, string>) =>
  values.map((value) => ({ value, label: labels[value] }));

function fromIndicator(indicator: IndicatorListItem): Values {
  return {
    type: indicator.type,
    value: indicator.value,
    severity: indicator.severity,
    verdict: indicator.verdict,
    status: indicator.status,
    confidence: String(indicator.confidence),
    source: indicator.source,
    description: indicator.description ?? "",
    first_seen: toDateTimeLocalValue(indicator.first_seen),
    last_seen: toDateTimeLocalValue(indicator.last_seen),
    tags: indicator.tags.map((tag) => tag.name),
  };
}

/** "" -> undefined; a local date-time from the browser -> an ISO timestamp with offset. */
function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? local : date.toISOString();
}

type Props = {
  /** Existing tag names, offered as suggestions. */
  tagOptions: string[];
} & ({ mode: "create"; indicator?: undefined } | { mode: "edit"; indicator: IndicatorListItem });

/**
 * Create and edit form. Type and value identify an indicator, so on edit they are shown but fixed
 * (delete and re-create to fix a typo). Input is validated with the same schemas as the API, so the
 * messages match, and the server still has the last word (duplicates, permissions, constraints).
 */
export function IndicatorForm({ mode, indicator, tagOptions }: Props) {
  const router = useRouter();
  const initial = indicator ? fromIndicator(indicator) : DEFAULTS;
  const [values, setValues] = useState<Values>(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [existingId, setExistingId] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const set = <K extends keyof Values>(key: K, value: Values[K]) =>
    setValues((current) => ({ ...current, [key]: value }));

  function checkValue() {
    const value = values.value.trim();
    const problem = value ? validateIndicatorValue(values.type, value) : null;
    setErrors((current) => (problem ? { ...current, value: problem } : without(current, "value")));
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setFormError(null);
    setExistingId(null);

    const confidence = values.confidence.trim() === "" ? undefined : Number(values.confidence);
    const common = {
      severity: values.severity,
      verdict: values.verdict,
      status: values.status,
      confidence,
      source: values.source,
      description: values.description,
      tags: values.tags,
    };

    // On edit only send dates the user actually changed: the field has minute precision, so echoing
    // an untouched value back would silently drop its seconds.
    const dates = {
      ...(mode === "create" || values.first_seen !== initial.first_seen
        ? { first_seen: toIso(values.first_seen) }
        : {}),
      ...(mode === "create" || values.last_seen !== initial.last_seen
        ? { last_seen: toIso(values.last_seen) }
        : {}),
    };
    const clean = <T extends object>(object: T) =>
      Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));

    const body =
      mode === "create"
        ? clean({ type: values.type, value: values.value, ...common, ...dates })
        : clean({ ...common, ...dates });

    const parsed =
      mode === "create"
        ? createIndicatorSchema.safeParse(body)
        : updateIndicatorSchema.safeParse(body);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }

    setErrors({});
    setPending(true);
    const result =
      mode === "create"
        ? await apiFetch<IndicatorListItem>("/api/indicators", { body: parsed.data })
        : await apiFetch<IndicatorListItem>(`/api/indicators/${indicator.id}`, {
            method: "PATCH",
            body: parsed.data,
          });

    if (!result.ok) {
      setPending(false);
      setErrors(result.fieldErrors);
      setFormError(result.message);
      if (result.status === 409) {
        // The API names the existing indicator so the user can go and look at it.
        const id = (result.details as { existing_id?: unknown } | undefined)?.existing_id;
        setExistingId(typeof id === "string" ? id : null);
      }
      return;
    }

    router.push(`/indicators/${result.data.id}`);
    router.refresh();
  }

  const cancelHref = indicator ? `/indicators/${indicator.id}` : "/indicators";

  return (
    <form
      onSubmit={onSubmit}
      noValidate
      className="space-y-6"
      aria-label={mode === "create" ? "New indicator" : "Edit indicator"}
    >
      {formError && (
        <Alert tone="error">
          {formError}{" "}
          {existingId && (
            <Link href={`/indicators/${existingId}`} className="font-semibold underline">
              View the existing indicator
            </Link>
          )}
        </Alert>
      )}

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Indicator</legend>
        {mode === "create" ? (
          <div className="grid gap-4 sm:grid-cols-[14rem_minmax(0,1fr)]">
            <SelectField
              id="type"
              label="Type"
              required
              value={values.type}
              onChange={(event) => {
                set("type", event.target.value as IndicatorType);
                setErrors((current) => without(current, "value"));
              }}
              options={options(INDICATOR_TYPES, INDICATOR_TYPE_LABELS)}
              error={errors.type}
            />
            <TextField
              id="value"
              label="Value"
              required
              value={values.value}
              onChange={(event) => set("value", event.target.value)}
              onBlur={checkValue}
              placeholder={VALUE_HINTS[values.type].placeholder}
              autoComplete="off"
              spellCheck={false}
              autoCapitalize="none"
              maxLength={2048}
              className="font-mono"
              error={errors.value}
              hint="Spaces around the value are removed; hosts, hashes and emails are stored in lower case."
            />
          </div>
        ) : (
          <dl className="grid gap-x-6 gap-y-1 rounded-lg border border-border bg-surface-2/50 p-3 text-sm sm:grid-cols-[8rem_minmax(0,1fr)]">
            <dt className="text-muted">Type</dt>
            <dd>{INDICATOR_TYPE_LABELS[initial.type]}</dd>
            <dt className="text-muted">Value</dt>
            <dd className="font-mono break-all">{initial.value}</dd>
            <dd className="text-xs text-muted sm:col-span-2">
              The type and value identify the indicator and cannot be changed. To fix a typo, delete
              it and add it again.
            </dd>
          </dl>
        )}
      </fieldset>

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Assessment</legend>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <SelectField
            id="verdict"
            label="Verdict"
            value={values.verdict}
            onChange={(event) => set("verdict", event.target.value as Verdict)}
            options={options(VERDICTS, VERDICT_LABELS)}
            error={errors.verdict}
          />
          <SelectField
            id="severity"
            label="Severity"
            value={values.severity}
            onChange={(event) => set("severity", event.target.value as Severity)}
            options={options(SEVERITIES, SEVERITY_LABELS)}
            error={errors.severity}
          />
          <SelectField
            id="status"
            label="Status"
            value={values.status}
            onChange={(event) => set("status", event.target.value as IndicatorStatus)}
            options={options(INDICATOR_STATUSES, INDICATOR_STATUS_LABELS)}
            error={errors.status}
          />
          <TextField
            id="confidence"
            label="Confidence (0–100)"
            type="number"
            inputMode="numeric"
            min={0}
            max={100}
            step={1}
            value={values.confidence}
            onChange={(event) => set("confidence", event.target.value)}
            error={errors.confidence}
          />
        </div>
      </fieldset>

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Context</legend>
        <TextAreaField
          id="description"
          label="Description"
          value={values.description}
          onChange={(event) => set("description", event.target.value)}
          maxLength={5000}
          rows={4}
          placeholder="What was observed, and why it matters."
          error={errors.description}
        />
        <TagInput
          id="tags"
          label="Tags"
          value={values.tags}
          onChange={(tags) => set("tags", tags)}
          suggestions={tagOptions}
          error={errors.tags}
        />
        <div className="grid gap-4 sm:grid-cols-3">
          <TextField
            id="source"
            label="Source"
            value={values.source}
            onChange={(event) => set("source", event.target.value)}
            maxLength={100}
            hint="Where you learned about it, for example a report or feed."
            error={errors.source}
          />
          <TextField
            id="first_seen"
            label="First seen"
            type="datetime-local"
            value={values.first_seen}
            onChange={(event) => set("first_seen", event.target.value)}
            hint={mode === "create" ? "Leave empty for now." : undefined}
            error={errors.first_seen}
          />
          <TextField
            id="last_seen"
            label="Last seen"
            type="datetime-local"
            value={values.last_seen}
            onChange={(event) => set("last_seen", event.target.value)}
            hint={mode === "create" ? "Leave empty for now." : undefined}
            error={errors.last_seen}
          />
        </div>
        {mode === "create" && (
          <p className="text-xs text-muted">
            New indicators are recorded as <strong className="font-semibold">Local</strong> data:
            entered by your team, not verified by an external provider.
          </p>
        )}
      </fieldset>

      <div className="flex flex-wrap gap-3 border-t border-border pt-5">
        <Button type="submit" loading={pending}>
          {pending ? "Saving…" : mode === "create" ? "Create indicator" : "Save changes"}
        </Button>
        <Link href={cancelHref} className={buttonClasses({ variant: "secondary" })}>
          Cancel
        </Link>
      </div>
    </form>
  );
}
