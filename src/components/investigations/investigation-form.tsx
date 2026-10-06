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
import { ASSIGNEE_ME } from "@/lib/alerts/constants";
import { personWithRole } from "@/lib/format";
import { PRIORITIES, PRIORITY_LABELS } from "@/lib/investigations/constants";
import { createInvestigationSchema } from "@/lib/investigations/schema";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import type { Priority } from "@/types/domain";

type Person = { id: string; display_name: string | null; role?: string };

/** Opens an investigation. It starts `open`, is saved as local data and is assigned to you unless you pick someone else. */
export function InvestigationForm({
  people,
  tagOptions,
}: {
  people: Person[];
  tagOptions: string[];
}) {
  const router = useRouter();
  const [values, setValues] = useState({
    title: "",
    description: "",
    priority: "medium" as Priority,
    analyst: ASSIGNEE_ME,
    tags: [] as string[],
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const set = <K extends keyof typeof values>(key: K, value: (typeof values)[K]) =>
    setValues((current) => ({ ...current, [key]: value }));

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setFormError(null);

    const parsed = createInvestigationSchema.safeParse({
      title: values.title,
      description: values.description,
      priority: values.priority,
      analyst_id: values.analyst === "" ? null : values.analyst,
      tags: values.tags,
    });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    setPending(true);
    const result = await apiFetch<{ id: string }>("/api/investigations", { body: parsed.data });
    if (!result.ok) {
      setPending(false);
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    router.push(`/investigations/${result.data.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-5" aria-label="New investigation">
      {formError && <Alert tone="error">{formError}</Alert>}
      <TextField
        id="title"
        label="Title"
        required
        value={values.title}
        onChange={(event) => set("title", event.target.value)}
        maxLength={300}
        error={errors.title}
      />
      <TextAreaField
        id="description"
        label="Description"
        value={values.description}
        onChange={(event) => set("description", event.target.value)}
        maxLength={10000}
        rows={5}
        error={errors.description}
        hint="What you are trying to find out, and why."
      />
      <div className="grid gap-4 sm:grid-cols-2">
        <SelectField
          id="priority"
          label="Priority"
          value={values.priority}
          onChange={(event) => set("priority", event.target.value as Priority)}
          options={PRIORITIES.map((value) => ({ value, label: PRIORITY_LABELS[value] }))}
          error={errors.priority}
        />
        <SelectField
          id="analyst"
          label="Analyst"
          value={values.analyst}
          onChange={(event) => set("analyst", event.target.value)}
          options={[
            { value: ASSIGNEE_ME, label: "Me" },
            { value: "", label: "Unassigned" },
            ...people.map((person) => ({ value: person.id, label: personWithRole(person) })),
          ]}
          error={errors.analyst_id}
        />
      </div>
      <TagInput
        id="tags"
        label="Tags"
        value={values.tags}
        onChange={(tags) => set("tags", tags)}
        suggestions={tagOptions}
        error={errors.tags}
      />
      <div className="flex items-center gap-3">
        <Button type="submit" loading={pending}>
          Open investigation
        </Button>
        <Link href="/investigations" className={buttonClasses({ variant: "ghost" })}>
          Cancel
        </Link>
      </div>
    </form>
  );
}
