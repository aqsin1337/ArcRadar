"use client";

import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { apiFetch } from "@/lib/api/client";
import type { AiAvailability, AiProviderId } from "@/lib/ai/types";

const NONE = "";

/**
 * Which AI provider answers "ask AI" clicks across the app. Only a provider that is both configured
 * (a server-side key/URL is set) and enabled can be chosen; an administrator picks one at a time and
 * an optional model name, or clears the choice to turn AI features off everywhere.
 */
export function AiProviderPicker({
  availability,
  canManage,
}: {
  availability: AiAvailability;
  canManage: boolean;
}) {
  const [state, setState] = useState(availability);
  const [provider, setProvider] = useState<string>(state.active_provider ?? NONE);
  const [model, setModel] = useState(state.active_model ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const selectable = state.providers.filter((p) => p.configured && p.enabled);
  const activeStatus = state.active_provider
    ? state.providers.find((p) => p.id === state.active_provider)
    : undefined;

  async function save() {
    if (pending) return;
    setPending(true);
    setError(null);
    setSaved(false);
    const result = await apiFetch<AiAvailability>("/api/ai/settings", {
      method: "PATCH",
      body: {
        active_provider: provider === NONE ? null : (provider as AiProviderId),
        active_model: provider === NONE ? null : model.trim() === "" ? null : model.trim(),
      },
    });
    setPending(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setState(result.data);
    setSaved(true);
  }

  if (!canManage) {
    return (
      <div className="space-y-1 text-sm">
        {state.active_provider ? (
          <p>
            Active provider:{" "}
            <span className="font-medium">{activeStatus?.name ?? state.active_provider}</span>
            {state.active_model && <span className="text-muted"> ({state.active_model})</span>}
            {!state.ready && (
              <Badge tone="amber" className="ml-2">
                Not ready
              </Badge>
            )}
          </p>
        ) : (
          <p className="text-muted">
            No AI provider is active. Ask an administrator to choose one.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="ai-provider-picker">
      {error && <Alert tone="error">{error}</Alert>}
      {saved && !error && <Alert tone="success">Saved.</Alert>}
      {selectable.length === 0 && (
        <p className="text-sm text-muted">
          No AI provider is both configured and enabled yet. Set a server-side key (or, for Ollama,
          its base URL) and enable the provider above, then it appears here.
        </p>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="block space-y-1">
          <span className="text-xs font-medium text-muted">Active provider</span>
          <Select
            value={provider}
            onChange={(event) => {
              setSaved(false);
              setProvider(event.target.value);
            }}
            className="h-9 w-56"
          >
            <option value={NONE}>None (AI features off)</option>
            {selectable.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </label>
        <TextField
          id="ai-active-model"
          label="Model (optional)"
          placeholder="Provider default"
          value={model}
          disabled={provider === NONE}
          onChange={(event) => {
            setSaved(false);
            setModel(event.target.value);
          }}
          className="h-9 w-56"
        />
        <Button type="button" loading={pending} onClick={save}>
          Save
        </Button>
      </div>
    </div>
  );
}
