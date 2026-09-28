"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { SelectField } from "@/components/ui/select";
import { EntityPicker } from "@/components/ui/entity-picker";
import { apiFetch } from "@/lib/api/client";
import {
  REPORT_TYPES,
  REPORT_TYPE_DESCRIPTIONS,
  REPORT_TYPE_LABELS,
} from "@/lib/reports/constants";
import type { CreateReportInput } from "@/lib/reports/schema";
import type { ReportType } from "@/types/domain";

type Hit = { id: string; name?: string; title?: string };

async function searchList(path: string, signal: AbortSignal): Promise<Hit[] | null> {
  const result = await apiFetch<{ items: Hit[] }>(path, { signal });
  return result.ok ? result.data.items : null;
}

/** Generates a report: pick a type, name a target when the type needs one, an optional title. */
export function NewReportForm() {
  const router = useRouter();
  const [type, setType] = useState<ReportType>("alerts");
  const [target, setTarget] = useState<Hit | null>(null);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const needsTarget = type === "investigation" || type === "threat_actor";

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    if (needsTarget && !target) {
      setError(`Choose ${type === "investigation" ? "an investigation" : "a threat actor"}.`);
      return;
    }

    const body: CreateReportInput =
      type === "investigation"
        ? { type, title: title || undefined, investigation_id: target!.id }
        : type === "threat_actor"
          ? { type, title: title || undefined, threat_actor_id: target!.id }
          : { type, title: title || undefined };

    setPending(true);
    setError(null);
    const result = await apiFetch<{ id: string }>("/api/reports", { body });
    setPending(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.push(`/reports/${result.data.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} noValidate className="max-w-lg space-y-5" aria-label="New report">
      {error && <Alert tone="error">{error}</Alert>}
      <SelectField
        id="report-type"
        label="Type"
        hint={REPORT_TYPE_DESCRIPTIONS[type]}
        value={type}
        onChange={(event) => {
          setType(event.target.value as ReportType);
          setTarget(null);
          setError(null);
        }}
        options={REPORT_TYPES.map((value) => ({ value, label: REPORT_TYPE_LABELS[value] }))}
      />

      {type === "investigation" && (
        <EntityPicker<Hit>
          id="report-investigation"
          label="Investigation"
          placeholder="Search investigations by title"
          search={(text, signal) =>
            searchList(`/api/investigations?q=${encodeURIComponent(text)}&page_size=8`, signal)
          }
          renderItem={(item) => item.title}
          onPick={setTarget}
        />
      )}
      {type === "threat_actor" && (
        <EntityPicker<Hit>
          id="report-actor"
          label="Threat actor"
          placeholder="Search threat actors by name"
          search={(text, signal) =>
            searchList(`/api/threat-actors?q=${encodeURIComponent(text)}&page_size=8`, signal)
          }
          renderItem={(item) => item.name}
          onPick={setTarget}
        />
      )}
      {needsTarget && target && (
        <p className="text-sm text-muted">
          Selected:{" "}
          <span className="font-medium text-foreground">{target.title ?? target.name}</span>
        </p>
      )}

      <TextField
        id="report-title"
        label="Title"
        hint="Leave blank for a generated one."
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        maxLength={300}
      />

      <Button type="submit" loading={pending}>
        Generate report
      </Button>
    </form>
  );
}
