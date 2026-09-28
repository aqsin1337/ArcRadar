"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { LinkPicker } from "@/components/ui/link-picker";
import { SelectField } from "@/components/ui/select";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import { toDateTimeLocalValue } from "@/lib/format";
import { CAMPAIGN_STATUSES, CAMPAIGN_STATUS_LABELS } from "@/lib/threat-intel/constants";
import { createCampaignSchema, updateCampaignSchema } from "@/lib/threat-intel/schema";
import type { CampaignDetail, LinkOptions } from "@/lib/threat-intel/types";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import type { CampaignStatus } from "@/types/domain";
import { dateBody } from "./form-helpers";

type Values = {
  name: string;
  description: string;
  status: CampaignStatus;
  first_seen: string;
  last_seen: string;
  actor_ids: string[];
};

const EMPTY: Values = {
  name: "",
  description: "",
  status: "active",
  first_seen: "",
  last_seen: "",
  actor_ids: [],
};

function fromCampaign(campaign: CampaignDetail): Values {
  return {
    name: campaign.name,
    description: campaign.description ?? "",
    status: campaign.status,
    first_seen: campaign.first_seen ? toDateTimeLocalValue(campaign.first_seen) : "",
    last_seen: campaign.last_seen ? toDateTimeLocalValue(campaign.last_seen) : "",
    actor_ids: campaign.actors.map((item) => item.id),
  };
}

type Props = { options: LinkOptions } & (
  { mode: "create"; campaign?: undefined } | { mode: "edit"; campaign: CampaignDetail }
);

/** Create and edit form for a campaign (administrators), validated with the API's own schemas. */
export function CampaignForm({ mode, campaign, options }: Props) {
  const router = useRouter();
  const initial = campaign ? fromCampaign(campaign) : EMPTY;
  const [values, setValues] = useState<Values>(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const set = <K extends keyof Values>(key: K, value: Values[K]) =>
    setValues((current) => ({ ...current, [key]: value }));

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setFormError(null);

    const body = {
      name: values.name,
      description: values.description,
      status: values.status,
      ...dateBody(mode, values, initial),
      actor_ids: values.actor_ids,
    };
    const parsed =
      mode === "create"
        ? createCampaignSchema.safeParse(body)
        : updateCampaignSchema.safeParse(body);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }

    setErrors({});
    setPending(true);
    const result =
      mode === "create"
        ? await apiFetch<{ id: string }>("/api/campaigns", { body: parsed.data })
        : await apiFetch<{ id: string }>(`/api/campaigns/${campaign.id}`, {
            method: "PATCH",
            body: parsed.data,
          });
    if (!result.ok) {
      setPending(false);
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    router.push(`/campaigns/${result.data.id}`);
    router.refresh();
  }

  const cancelHref = campaign ? `/campaigns/${campaign.id}` : "/campaigns";

  return (
    <form
      onSubmit={onSubmit}
      noValidate
      className="space-y-6"
      aria-label={mode === "create" ? "New campaign" : "Edit campaign"}
    >
      {formError && <Alert tone="error">{formError}</Alert>}

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Campaign</legend>
        <TextField
          id="name"
          label="Name"
          required
          value={values.name}
          onChange={(event) => set("name", event.target.value)}
          maxLength={200}
          error={errors.name}
        />
        <TextAreaField
          id="description"
          label="Description"
          value={values.description}
          onChange={(event) => set("description", event.target.value)}
          maxLength={10000}
          rows={5}
          error={errors.description}
        />
        <div className="grid gap-4 sm:grid-cols-3">
          <SelectField
            id="status"
            label="Status"
            value={values.status}
            onChange={(event) => set("status", event.target.value as CampaignStatus)}
            options={CAMPAIGN_STATUSES.map((value) => ({
              value,
              label: CAMPAIGN_STATUS_LABELS[value],
            }))}
            error={errors.status}
          />
          <TextField
            id="first_seen"
            label="First seen"
            type="datetime-local"
            value={values.first_seen}
            onChange={(event) => set("first_seen", event.target.value)}
            error={errors.first_seen}
          />
          <TextField
            id="last_seen"
            label="Last seen"
            type="datetime-local"
            value={values.last_seen}
            onChange={(event) => set("last_seen", event.target.value)}
            error={errors.last_seen}
          />
        </div>
      </fieldset>

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Links</legend>
        <LinkPicker
          label="Threat actors"
          options={options.actors.map((item) => ({ value: item.id, label: item.name }))}
          value={values.actor_ids}
          onChange={(ids) => set("actor_ids", ids)}
          emptyText="No threat actors yet."
          error={errors.actor_ids}
        />
        {mode === "create" && (
          <p className="text-xs text-muted">
            New campaigns are recorded as <strong className="font-semibold">Local</strong> data:
            written by your team, not verified by an external provider.
          </p>
        )}
      </fieldset>

      <div className="flex flex-wrap gap-3 border-t border-border pt-5">
        <Button type="submit" loading={pending}>
          {pending ? "Saving…" : mode === "create" ? "Create campaign" : "Save changes"}
        </Button>
        <Link href={cancelHref} className={buttonClasses({ variant: "secondary" })}>
          Cancel
        </Link>
      </div>
    </form>
  );
}
