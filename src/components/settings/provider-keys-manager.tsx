"use client";

import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/api/client";
import { SECRET_GROUPS } from "@/lib/secrets/catalog";
import type { SecretView, SecretsOverview } from "@/lib/secrets/service";

const SOURCE_LABEL: Record<SecretView["source"], { text: string; tone: Tone }> = {
  app: { text: "Saved in ArcRadar", tone: "green" },
  server: { text: "From server settings", tone: "blue" },
  none: { text: "Not set", tone: "slate" },
};

function SecretRow({
  secret,
  canSave,
  onChanged,
}: {
  secret: SecretView;
  canSave: boolean;
  onChanged: (next: SecretsOverview) => void;
}) {
  const [draft, setDraft] = useState(secret.kind === "text" ? (secret.value ?? "") : "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = SOURCE_LABEL[secret.source];
  const inputId = `secret-${secret.name}`;

  async function send(method: "PUT" | "DELETE", value?: string) {
    setPending(true);
    setError(null);
    const result = await apiFetch<SecretsOverview>(`/api/secrets/${secret.name}`, {
      method,
      body: method === "PUT" ? { value } : undefined,
    });
    setPending(false);
    if (!result.ok) {
      setError(result.fieldErrors.value ?? result.message);
      return;
    }
    if (secret.kind === "secret") setDraft("");
    onChanged(result.data);
  }

  return (
    <div className="space-y-2 border-b border-border py-4 last:border-b-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-sm font-medium">{secret.label}</p>
          <p className="text-xs text-muted">{secret.help}</p>
        </div>
        <Badge tone={status.tone}>
          {status.text}
          {secret.last4 ? ` · …${secret.last4}` : ""}
        </Badge>
      </div>

      {secret.kind === "flag" ? (
        <div className="flex gap-2">
          {secret.source === "app" ? (
            <Button
              size="sm"
              variant="secondary"
              disabled={pending || !canSave}
              onClick={() => send("DELETE")}
            >
              Turn off
            </Button>
          ) : (
            <Button
              size="sm"
              disabled={pending || !canSave || secret.source === "server"}
              onClick={() => send("PUT", "true")}
            >
              {secret.source === "server" ? "On (server setting)" : "Turn on"}
            </Button>
          )}
        </div>
      ) : (
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (draft.trim()) void send("PUT", draft);
          }}
        >
          <label htmlFor={inputId} className="sr-only">
            {secret.label}
          </label>
          <Input
            id={inputId}
            type={secret.kind === "secret" ? "password" : "text"}
            autoComplete="off"
            spellCheck={false}
            value={draft}
            invalid={error !== null}
            disabled={pending || !canSave}
            placeholder={
              secret.kind === "secret"
                ? secret.source === "app"
                  ? "Paste a new key to replace it"
                  : "Paste the key"
                : "Not set"
            }
            onChange={(event) => setDraft(event.target.value)}
            className="min-w-0 flex-1 basis-64"
          />
          <Button type="submit" size="sm" disabled={pending || !canSave || draft.trim() === ""}>
            {pending ? "Saving…" : "Save"}
          </Button>
          {secret.source === "app" && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={pending || !canSave}
              onClick={() => send("DELETE")}
            >
              Remove
            </Button>
          )}
        </form>
      )}
      {error && (
        <p role="alert" className="text-sm text-tone-red-fg">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Administrators paste provider keys here instead of editing server settings. A saved key is
 * encrypted before it is stored and never shown again (only its last four characters).
 */
export function ProviderKeysManager({ initial }: { initial: SecretsOverview }) {
  const [overview, setOverview] = useState(initial);

  return (
    <div className="space-y-4">
      {!overview.encryption_ready && (
        <Alert tone="warning" title="Saving keys here is not switched on yet">
          The server needs a SECRETS_ENCRYPTION_KEY setting (32 random bytes, base64) before keys
          can be stored. Keys already set on the server keep working.
        </Alert>
      )}
      {SECRET_GROUPS.map((group) => (
        <Card key={group}>
          <CardHeader>
            <CardTitle>{group}</CardTitle>
            <CardDescription>
              {group === "Threat intelligence" &&
                "Lookups and research on arrival use these. A provider with no key is simply skipped."}
              {group === "AI providers" &&
                "Save a key, then pick the active provider on the Integrations page."}
              {group === "Wazuh rules repository" &&
                "Where approved Wazuh rules are pushed. The Manager pulls them from there."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {overview.secrets
              .filter((secret) => secret.group === group)
              .map((secret) => (
                <SecretRow
                  key={`${secret.name}-${secret.source}-${secret.updated_at ?? ""}`}
                  secret={secret}
                  canSave={overview.encryption_ready}
                  onChanged={setOverview}
                />
              ))}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
