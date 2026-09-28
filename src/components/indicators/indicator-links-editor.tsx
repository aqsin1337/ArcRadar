"use client";

import { Pencil } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { LinkPicker } from "@/components/ui/link-picker";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import type { LinkOptions } from "@/lib/threat-intel/types";

type Selection = { actor_ids: string[]; campaign_ids: string[]; malware_ids: string[] };

/**
 * "Edit links": choose the threat actors, campaigns and malware families an indicator belongs to
 * (analysts and administrators). Saving replaces the three sets; the page refreshes afterwards.
 */
export function IndicatorLinksEditor({
  indicatorId,
  options,
  initial,
}: {
  indicatorId: string;
  options: LinkOptions;
  initial: Selection;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [values, setValues] = useState<Selection>(initial);
  const { pending, error, run, clearError } = useAction();

  const set = (key: keyof Selection) => (ids: string[]) =>
    setValues((current) => ({ ...current, [key]: ids }));

  if (!open) {
    return (
      <Button
        variant="secondary"
        size="sm"
        onClick={() => {
          setValues(initial);
          setOpen(true);
        }}
      >
        <Pencil aria-hidden className="size-4" />
        Edit links
      </Button>
    );
  }

  return (
    <form
      aria-label="Edit linked intelligence"
      className="space-y-4 rounded-lg border border-border bg-surface-2/40 p-4"
      onSubmit={(event) => {
        event.preventDefault();
        void run(
          "save",
          () => apiFetch(`/api/indicators/${indicatorId}/links`, { method: "PUT", body: values }),
          () => {
            setOpen(false);
            router.refresh(); // the page is server-rendered: refresh it so the saved links show
          },
        );
      }}
    >
      {error && <Alert tone="error">{error}</Alert>}
      <div className="grid gap-4 lg:grid-cols-3">
        <LinkPicker
          label="Threat actors"
          options={options.actors.map((item) => ({ value: item.id, label: item.name }))}
          value={values.actor_ids}
          onChange={set("actor_ids")}
          emptyText="No threat actors yet."
        />
        <LinkPicker
          label="Campaigns"
          options={options.campaigns.map((item) => ({ value: item.id, label: item.name }))}
          value={values.campaign_ids}
          onChange={set("campaign_ids")}
          emptyText="No campaigns yet."
        />
        <LinkPicker
          label="Malware"
          options={options.malware.map((item) => ({
            value: item.id,
            label: item.name,
            detail: item.malware_type,
          }))}
          value={values.malware_ids}
          onChange={set("malware_ids")}
          emptyText="No malware families yet."
        />
      </div>
      <div className="flex gap-2">
        <Button type="submit" size="sm" loading={pending === "save"}>
          Save links
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={pending !== null}
          onClick={() => {
            clearError();
            setOpen(false);
          }}
        >
          Cancel
        </Button>
      </div>
    </form>
  );
}
