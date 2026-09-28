"use client";

import { Check, Copy, KeyRound, Plus } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { TextField } from "@/components/ui/input";
import { SelectField } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/states";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { SCOPE_LABELS, type ApiKeyScope } from "@/lib/api-keys/constants";
import { formatRelative } from "@/lib/format";
import type { ApiKeyView } from "@/lib/api-keys/types";

const STATUS_TONE: Record<ApiKeyView["status"], Tone> = {
  active: "green",
  expired: "slate",
  revoked: "red",
};

const EXPIRY_OPTIONS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year (default)" },
  { value: "never", label: "Never" },
];

function NewKeyDialog({
  scopes,
  onCreated,
  onCancel,
}: {
  scopes: readonly ApiKeyScope[];
  onCreated: (key: string, row: ApiKeyView) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<ApiKeyScope | "">(scopes[0] ?? "");
  const [expires, setExpires] = useState("365");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!scope) return;
    setPending(true);
    setError(null);
    const result = await apiFetch<{ key: string; api_key: ApiKeyView }>("/api/api-keys", {
      body: {
        name,
        scopes: [scope],
        expires_in_days: expires === "never" ? null : Number(expires),
      },
    });
    setPending(false);
    if (!result.ok) {
      setError(result.fieldErrors.name ?? result.message);
      return;
    }
    onCreated(result.data.key, result.data.api_key);
  }

  return (
    <ConfirmDialog
      open
      title="New API key"
      confirmLabel={pending ? "Creating…" : "Create key"}
      pending={pending}
      error={error}
      onConfirm={submit}
      onCancel={onCancel}
      description={
        <div className="space-y-4 text-left">
          <TextField
            id="key-name"
            label="Name"
            hint="What this key is for, for example the machine or Manager that will use it."
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={100}
            required
          />
          <SelectField
            id="key-scope"
            label="Scope"
            value={scope}
            onChange={(event) => setScope(event.target.value as ApiKeyScope)}
            options={scopes.map((value) => ({ value, label: SCOPE_LABELS[value] }))}
          />
          <SelectField
            id="key-expiry"
            label="Expires"
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            options={EXPIRY_OPTIONS}
          />
        </div>
      }
    />
  );
}

function ShowKeyDialog({ apiKey, onClose }: { apiKey: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <ConfirmDialog
      open
      title="Your new API key"
      confirmLabel="Done"
      onConfirm={onClose}
      onCancel={onClose}
      description={
        <div className="space-y-3 text-left">
          <Alert tone="warning">
            This is shown once. Copy it now — ArcRadar keeps only its hash and cannot show it again.
          </Alert>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 p-2">
            <code className="min-w-0 flex-1 overflow-x-auto text-xs [overflow-wrap:anywhere]">
              {apiKey}
            </code>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={async () => {
                await navigator.clipboard.writeText(apiKey);
                setCopied(true);
              }}
            >
              {copied ? (
                <Check aria-hidden className="size-4" />
              ) : (
                <Copy aria-hidden className="size-4" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
      }
    />
  );
}

/** Create, list and revoke API keys. `scopes` is what the caller's role may issue (never empty). */
export function ApiKeysManager({
  keys,
  scopes,
  now,
}: {
  keys: ApiKeyView[];
  scopes: readonly ApiKeyScope[];
  now: Date;
}) {
  const { pending, error, run } = useAction();
  const [rows, setRows] = useState(keys);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiKeyView | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      {error && <Alert tone="error">{error}</Alert>}
      <div className="flex justify-end">
        <Button onClick={() => setCreating(true)}>
          <Plus aria-hidden className="size-4" />
          New key
        </Button>
      </div>

      {rows.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No API keys yet"
          description="Make one for a Wazuh Manager or another machine that sends data to ArcRadar."
        />
      ) : (
        <Table caption="API keys">
          <THead>
            <Tr>
              <Th>Name</Th>
              <Th className="hidden @lg:table-cell">Scope</Th>
              <Th>Status</Th>
              <Th className="hidden @xl:table-cell">Last used</Th>
              <Th className="hidden @xl:table-cell">Expires</Th>
              <Th className="text-right">
                <span className="sr-only">Actions</span>
              </Th>
            </Tr>
          </THead>
          <TBody>
            {rows.map((key) => (
              <Tr key={key.id}>
                <Td>
                  <span className="font-medium">{key.name}</span>
                  <span className="block font-mono text-xs text-muted">{key.key_prefix}…</span>
                </Td>
                <Td className="hidden @lg:table-cell">
                  {key.scopes
                    .map((scope) => SCOPE_LABELS[scope as ApiKeyScope] ?? scope)
                    .join(", ")}
                </Td>
                <Td>
                  <Badge tone={STATUS_TONE[key.status]}>{key.status}</Badge>
                </Td>
                <Td className="hidden @xl:table-cell text-muted">
                  {key.last_used_at ? formatRelative(key.last_used_at, now) : "Never"}
                </Td>
                <Td className="hidden @xl:table-cell text-muted">
                  {key.expires_at ? formatRelative(key.expires_at, now) : "Never"}
                </Td>
                <Td className="text-right">
                  {key.status !== "revoked" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setRevoking(key)}
                      disabled={pending !== null}
                    >
                      Revoke
                    </Button>
                  )}
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      )}

      {creating && (
        <NewKeyDialog
          scopes={scopes}
          onCancel={() => setCreating(false)}
          onCreated={(key, row) => {
            setRows((current) => [row, ...current]);
            setCreating(false);
            setNewKey(key);
          }}
        />
      )}
      {newKey && <ShowKeyDialog apiKey={newKey} onClose={() => setNewKey(null)} />}
      {revoking && (
        <ConfirmDialog
          open
          title="Revoke this key?"
          description={
            <>
              <strong className="font-semibold text-foreground">{revoking.name}</strong> will stop
              working immediately. This cannot be undone.
            </>
          }
          confirmLabel="Revoke"
          pending={pending === revoking.id}
          error={error}
          onConfirm={() =>
            run(
              revoking.id,
              () => apiFetch(`/api/api-keys/${revoking.id}`, { method: "DELETE" }),
              () => {
                setRows((current) =>
                  current.map((row) =>
                    row.id === revoking.id ? { ...row, status: "revoked" as const } : row,
                  ),
                );
                setRevoking(null);
              },
            )
          }
          onCancel={() => setRevoking(null)}
        />
      )}
    </div>
  );
}
