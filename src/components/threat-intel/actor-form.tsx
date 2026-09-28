"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { LinkPicker } from "@/components/ui/link-picker";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import { toDateTimeLocalValue } from "@/lib/format";
import { createActorSchema, updateActorSchema } from "@/lib/threat-intel/schema";
import type { ActorDetail, LinkOptions } from "@/lib/threat-intel/types";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import { dateBody, joinList, splitList } from "./form-helpers";

type Values = {
  name: string;
  aliases: string;
  description: string;
  motivation: string;
  attribution_country: string;
  target_industries: string;
  target_countries: string;
  first_seen: string;
  last_seen: string;
  malware_ids: string[];
  campaign_ids: string[];
  technique_ids: string[];
};

const EMPTY: Values = {
  name: "",
  aliases: "",
  description: "",
  motivation: "",
  attribution_country: "",
  target_industries: "",
  target_countries: "",
  first_seen: "",
  last_seen: "",
  malware_ids: [],
  campaign_ids: [],
  technique_ids: [],
};

function fromActor(actor: ActorDetail): Values {
  return {
    name: actor.name,
    aliases: joinList(actor.aliases),
    description: actor.description ?? "",
    motivation: actor.motivation ?? "",
    attribution_country: actor.attribution_country ?? "",
    target_industries: joinList(actor.target_industries),
    target_countries: joinList(actor.target_countries),
    first_seen: actor.first_seen ? toDateTimeLocalValue(actor.first_seen) : "",
    last_seen: actor.last_seen ? toDateTimeLocalValue(actor.last_seen) : "",
    malware_ids: actor.malware.map((item) => item.id),
    campaign_ids: actor.campaigns.map((item) => item.id),
    technique_ids: actor.techniques.map((item) => item.id),
  };
}

type Props = { options: LinkOptions } & (
  { mode: "create"; actor?: undefined } | { mode: "edit"; actor: ActorDetail }
);

/**
 * Create and edit form for a threat actor (administrators). Input is checked with the same schemas as
 * the API; the server still has the last word (duplicate names, permissions, links that vanished).
 */
export function ActorForm({ mode, actor, options }: Props) {
  const router = useRouter();
  const initial = actor ? fromActor(actor) : EMPTY;
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
      aliases: splitList(values.aliases),
      description: values.description,
      motivation: values.motivation,
      attribution_country: values.attribution_country,
      target_industries: splitList(values.target_industries),
      target_countries: splitList(values.target_countries),
      ...dateBody(mode, values, initial),
      malware_ids: values.malware_ids,
      campaign_ids: values.campaign_ids,
      technique_ids: values.technique_ids,
    };
    const parsed =
      mode === "create" ? createActorSchema.safeParse(body) : updateActorSchema.safeParse(body);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }

    setErrors({});
    setPending(true);
    const result =
      mode === "create"
        ? await apiFetch<{ id: string }>("/api/threat-actors", { body: parsed.data })
        : await apiFetch<{ id: string }>(`/api/threat-actors/${actor.id}`, {
            method: "PATCH",
            body: parsed.data,
          });
    if (!result.ok) {
      setPending(false);
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    router.push(`/threat-actors/${result.data.id}`);
    router.refresh();
  }

  const cancelHref = actor ? `/threat-actors/${actor.id}` : "/threat-actors";

  return (
    <form
      onSubmit={onSubmit}
      noValidate
      className="space-y-6"
      aria-label={mode === "create" ? "New threat actor" : "Edit threat actor"}
    >
      {formError && <Alert tone="error">{formError}</Alert>}

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Profile</legend>
        <TextField
          id="name"
          label="Name"
          required
          value={values.name}
          onChange={(event) => set("name", event.target.value)}
          maxLength={200}
          error={errors.name}
        />
        <TextField
          id="aliases"
          label="Aliases"
          value={values.aliases}
          onChange={(event) => set("aliases", event.target.value)}
          hint="Other names the group is known by, separated by commas."
          error={errors.aliases}
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
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            id="motivation"
            label="Motivation"
            value={values.motivation}
            onChange={(event) => set("motivation", event.target.value)}
            maxLength={200}
            placeholder="Financial gain, espionage…"
            error={errors.motivation}
          />
          <TextField
            id="attribution_country"
            label="Attributed country"
            value={values.attribution_country}
            onChange={(event) => set("attribution_country", event.target.value)}
            maxLength={100}
            hint="Only documented attribution. Leave empty when unknown."
            error={errors.attribution_country}
          />
        </div>
      </fieldset>

      <fieldset className="space-y-4">
        <legend className="mb-3 text-sm font-semibold">Targets and activity</legend>
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            id="target_industries"
            label="Target industries"
            value={values.target_industries}
            onChange={(event) => set("target_industries", event.target.value)}
            hint="Separated by commas."
            error={errors.target_industries}
          />
          <TextField
            id="target_countries"
            label="Target countries"
            value={values.target_countries}
            onChange={(event) => set("target_countries", event.target.value)}
            hint="Separated by commas."
            error={errors.target_countries}
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
        <div className="grid gap-4 lg:grid-cols-3">
          <LinkPicker
            label="Malware"
            options={options.malware.map((item) => ({
              value: item.id,
              label: item.name,
              detail: item.malware_type,
            }))}
            value={values.malware_ids}
            onChange={(ids) => set("malware_ids", ids)}
            emptyText="No malware families yet."
            error={errors.malware_ids}
          />
          <LinkPicker
            label="Campaigns"
            options={options.campaigns.map((item) => ({ value: item.id, label: item.name }))}
            value={values.campaign_ids}
            onChange={(ids) => set("campaign_ids", ids)}
            emptyText="No campaigns yet."
            error={errors.campaign_ids}
          />
          <LinkPicker
            label="Techniques"
            options={options.techniques.map((item) => ({
              value: item.id,
              label: item.id,
              detail: item.name,
            }))}
            value={values.technique_ids}
            onChange={(ids) => set("technique_ids", ids)}
            emptyText="No techniques yet."
            error={errors.technique_ids}
          />
        </div>
        {mode === "create" && (
          <p className="text-xs text-muted">
            New threat actors are recorded as <strong className="font-semibold">Local</strong> data:
            written by your team, not verified by an external provider.
          </p>
        )}
      </fieldset>

      <div className="flex flex-wrap gap-3 border-t border-border pt-5">
        <Button type="submit" loading={pending}>
          {pending ? "Saving…" : mode === "create" ? "Create threat actor" : "Save changes"}
        </Button>
        <Link href={cancelHref} className={buttonClasses({ variant: "secondary" })}>
          Cancel
        </Link>
      </div>
    </form>
  );
}
