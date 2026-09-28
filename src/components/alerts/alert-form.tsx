"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { SelectField } from "@/components/ui/select";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import { createAlertSchema } from "@/lib/alerts/schema";
import { SEVERITIES, SEVERITY_LABELS } from "@/lib/indicators/constants";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import type { Severity } from "@/types/domain";

/** Records a manual alert (source `manual`, local data). Live alerts arrive through ingestion. */
export function AlertForm() {
  const router = useRouter();
  const [values, setValues] = useState({
    title: "",
    severity: "medium" as Severity,
    description: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setFormError(null);

    const parsed = createAlertSchema.safeParse(values);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    setPending(true);
    const result = await apiFetch<{ id: string }>("/api/alerts", { body: parsed.data });
    if (!result.ok) {
      setPending(false);
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    router.push(`/alerts/${result.data.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-5" aria-label="New alert">
      {formError && <Alert tone="error">{formError}</Alert>}
      <TextField
        id="title"
        label="Title"
        required
        value={values.title}
        onChange={(event) => setValues((current) => ({ ...current, title: event.target.value }))}
        maxLength={300}
        error={errors.title}
      />
      <SelectField
        id="severity"
        label="Severity"
        value={values.severity}
        onChange={(event) =>
          setValues((current) => ({ ...current, severity: event.target.value as Severity }))
        }
        options={SEVERITIES.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
        error={errors.severity}
      />
      <TextAreaField
        id="description"
        label="Description"
        value={values.description}
        onChange={(event) =>
          setValues((current) => ({ ...current, description: event.target.value }))
        }
        maxLength={5000}
        rows={5}
        error={errors.description}
        hint="What was seen, where, and why it matters."
      />
      <div className="flex items-center gap-3">
        <Button type="submit" loading={pending}>
          Create alert
        </Button>
        <Link href="/alerts" className={buttonClasses({ variant: "ghost" })}>
          Cancel
        </Link>
      </div>
    </form>
  );
}
