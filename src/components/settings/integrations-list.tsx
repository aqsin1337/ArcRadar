"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { humanize } from "@/components/ui/domain-badges";
import { apiFetch } from "@/lib/api/client";
import { FEED_GROUPS, type FeedGroup } from "@/lib/feeds/groups";
import { formatRelative } from "@/lib/format";
import type { IntegrationRow } from "@/lib/integrations/types";

type FeedResultRow = {
  feed: string;
  status: "ok" | "failed" | "disabled";
  fetched: number;
  created: number;
  updated: number;
  error?: string;
};

const FEED_LABELS: Record<string, string> = {
  urlhaus: "URLhaus",
  feodo: "Feodo Tracker",
  threatfox: "ThreatFox",
  cisa_kev: "CISA KEV",
};

/** One short line per feed: what arrived, or why it did not. */
function summarise(results: FeedResultRow[]): string {
  return results
    .map((entry) => {
      const name = FEED_LABELS[entry.feed] ?? entry.feed;
      if (entry.status === "disabled") return `${name}: paused.`;
      if (entry.status === "failed") return `${name}: failed (${entry.error ?? "unknown error"}).`;
      return `${name}: ${entry.created} new, ${entry.updated} refreshed of ${entry.fetched}.`;
    })
    .join(" ");
}

/** Every provider ArcRadar knows, whether it is configured, and (for administrators) a switch. */
export function IntegrationsList({
  integrations,
  canManage,
  now,
}: {
  integrations: IntegrationRow[];
  canManage: boolean;
  now: Date;
}) {
  const [rows, setRows] = useState(integrations);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState<string | null>(null);
  const [imported, setImported] = useState<Record<string, string>>({});

  async function importNow(group: FeedGroup) {
    setImporting(group);
    setError(null);
    const result = await apiFetch<FeedResultRow[]>("/api/feeds/import", {
      method: "POST",
      body: { groups: [group] },
    });
    setImporting(null);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setImported((current) => ({ ...current, [group]: summarise(result.data) }));
    if (result.data.some((entry) => entry.status === "ok")) {
      const at = new Date().toISOString();
      setRows((current) =>
        current.map((row) => (row.provider === group ? { ...row, last_sync_at: at } : row)),
      );
    }
  }

  async function toggle(provider: string, enabled: boolean) {
    setPending(provider);
    setError(null);
    // Optimistic: the checkbox is controlled, so it must flip in the same tick as the click, or
    // React's re-render (still holding the old value) snaps it straight back.
    setRows((current) =>
      current.map((row) => (row.provider === provider ? { ...row, enabled } : row)),
    );

    const result = await apiFetch<IntegrationRow>(`/api/integrations/${provider}`, {
      method: "PATCH",
      body: { enabled },
    });
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      setRows((current) =>
        current.map((row) => (row.provider === provider ? { ...row, enabled: !enabled } : row)),
      );
      return;
    }
    setRows((current) => current.map((row) => (row.provider === provider ? result.data : row)));
  }

  return (
    <div className="space-y-4">
      {error && <p className="text-sm text-tone-red-fg">{error}</p>}
      <ul className="grid gap-3 sm:grid-cols-2">
        {rows.map((row) => (
          <li key={row.provider}>
            <Card>
              <CardHeader className="flex-row items-start justify-between gap-2 space-y-0">
                <CardTitle className="text-base">{row.display_name}</CardTitle>
                <Badge tone={row.configured ? "green" : "slate"}>
                  {row.configured ? "Configured" : "Not configured"}
                </Badge>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-1.5">
                  {row.capabilities.map((capability) => (
                    <Badge key={capability} tone="slate">
                      {humanize(capability)}
                    </Badge>
                  ))}
                </div>
                {row.last_sync_at && (
                  <p className="text-xs text-muted">
                    Last received {formatRelative(row.last_sync_at, now)}.
                  </p>
                )}
                {(FEED_GROUPS as readonly string[]).includes(row.provider) && (
                  <div className="space-y-2">
                    <p className="text-xs text-muted">
                      Free public feed, no key needed. Imported when an administrator presses Import
                      now.
                    </p>
                    {canManage && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        disabled={importing !== null || !row.enabled}
                        onClick={() => importNow(row.provider as FeedGroup)}
                      >
                        {importing === row.provider ? "Importing…" : "Import now"}
                      </Button>
                    )}
                    {imported[row.provider] && (
                      <p role="status" className="text-xs text-muted">
                        {imported[row.provider]}
                      </p>
                    )}
                  </div>
                )}
                {canManage ? (
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={row.enabled}
                      disabled={pending === row.provider || row.provider === "demo"}
                      onChange={(event) => toggle(row.provider, event.target.checked)}
                      className="size-4 rounded border-input-border"
                    />
                    {row.provider === "demo"
                      ? "Always available"
                      : row.enabled
                        ? "Enabled"
                        : "Disabled"}
                  </label>
                ) : (
                  <p className="text-xs text-muted">{row.enabled ? "Enabled" : "Disabled"}</p>
                )}
              </CardContent>
            </Card>
          </li>
        ))}
      </ul>
    </div>
  );
}
