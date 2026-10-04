import "server-only";
import { writeAuditLog } from "@/lib/audit/write";
import {
  addSummaries,
  EMPTY_SUMMARY,
  recordExternalIndicators,
  type ExternalIndicatorRecord,
  type RecordSummary,
} from "@/lib/indicators/external";
import { getJson, getText } from "@/lib/intel/http";
import { ProviderError } from "@/lib/intel/types";
import { logError, logWarn } from "@/lib/log";
import { createAdminClient } from "@/lib/supabase/admin";
import type { Json } from "@/types/database";
import { FEED_GROUPS, type FeedGroup } from "./groups";
import { parseKevCatalog, type KevVulnerability } from "./kev";
import { parseFeodoJson, parseThreatFoxJson, parseUrlhausText } from "./parse";

/*
 * The manual import of public threat data (an administrator presses Import now; nothing runs on a timer). Everything runs on the server, only ever
 * reads from fixed HTTPS addresses written in this file (nothing a user or the database supplies
 * becomes a host), never follows a redirect, and stores through the service-role-only SQL functions
 * (record_external_indicators, import_external_vulnerabilities). Feeds fail independently: one being
 * down costs its own entries, nothing else. An administrator can pause a whole group on the
 * Integrations page; a paused group is skipped by "Import now".
 */

export { FEED_GROUPS, type FeedGroup } from "./groups";

export type FeedId = "urlhaus" | "feodo" | "threatfox" | "cisa_kev";

export type FeedResult = {
  feed: FeedId;
  group: FeedGroup;
  status: "ok" | "failed" | "disabled";
  /** Entries the feed contributed after ArcRadar's own filtering. */
  fetched: number;
  created: number;
  updated: number;
  /** Already tracked as the workspace's own (local or demo): left as they were. */
  untouched: number;
  skipped: number;
  /** A short, safe reason when the feed failed (never a URL, key or response body). */
  error?: string;
};

const FEED_TIMEOUT_MS = 30_000;

export type Definition = {
  id: FeedId;
  group: FeedGroup;
  baseUrl: string;
  path: string;
  maxBytes: number;
};

export const FEEDS: readonly Definition[] = [
  {
    id: "urlhaus",
    group: "abusech",
    baseUrl: "https://urlhaus.abuse.ch",
    path: "/downloads/text_recent/",
    maxBytes: 4 * 1024 * 1024,
  },
  {
    id: "feodo",
    group: "abusech",
    baseUrl: "https://feodotracker.abuse.ch",
    path: "/downloads/ipblocklist.json",
    maxBytes: 2 * 1024 * 1024,
  },
  {
    id: "threatfox",
    group: "abusech",
    baseUrl: "https://threatfox.abuse.ch",
    path: "/export/json/recent/",
    maxBytes: 16 * 1024 * 1024,
  },
  {
    id: "cisa_kev",
    group: "cisa_kev",
    baseUrl: "https://www.cisa.gov",
    path: "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    maxBytes: 8 * 1024 * 1024,
  },
];

export type FeedDeps = {
  now: () => Date;
  /** Text of a feed, or null when the address answers 404. */
  fetchText: (definition: Definition, signal: AbortSignal) => Promise<string | null>;
  fetchJson: (definition: Definition, signal: AbortSignal) => Promise<unknown | null>;
  recordIndicators: (
    source: string,
    records: readonly ExternalIndicatorRecord[],
  ) => Promise<RecordSummary>;
  recordVulnerabilities: (records: readonly KevVulnerability[]) => Promise<RecordSummary>;
  /** Which groups an administrator has left switched on. */
  enabledGroups: () => Promise<ReadonlySet<FeedGroup>>;
  markSynced: (group: FeedGroup) => Promise<void>;
};

const request = (definition: Definition, signal: AbortSignal) => ({
  baseUrl: definition.baseUrl,
  path: definition.path,
  headers: {},
  signal,
  maxBytes: definition.maxBytes,
});

async function storeVulnerabilities(records: readonly KevVulnerability[]): Promise<RecordSummary> {
  const admin = createAdminClient();
  let total = EMPTY_SUMMARY;
  for (let i = 0; i < records.length; i += 500) {
    const { data, error } = await admin.rpc("import_external_vulnerabilities", {
      p_records: records.slice(i, i + 500) as unknown as Json,
    });
    if (error) throw new Error(error.message);
    const r = data as unknown as {
      imported: number;
      updated: number;
      untouched: number;
      skipped: number;
    };
    total = addSummaries(total, {
      created: r.imported,
      updated: r.updated,
      untouched: r.untouched,
      skipped: r.skipped,
    });
  }
  return total;
}

export function defaultFeedDeps(): FeedDeps {
  return {
    now: () => new Date(),
    fetchText: (definition, signal) => getText(request(definition, signal)),
    fetchJson: (definition, signal) => getJson(request(definition, signal)),
    recordIndicators: recordExternalIndicators,
    recordVulnerabilities: storeVulnerabilities,
    enabledGroups: async () => {
      const { data, error } = await createAdminClient()
        .from("integrations")
        .select("provider, enabled")
        .in("provider", [...FEED_GROUPS]);
      if (error) throw new Error(error.message);
      return new Set(data.filter((row) => row.enabled).map((row) => row.provider as FeedGroup));
    },
    markSynced: async (group) => {
      await createAdminClient()
        .from("integrations")
        .update({ last_sync_at: new Date().toISOString() })
        .eq("provider", group);
    },
  };
}

function reasonOf(error: unknown): string {
  if (error instanceof ProviderError) return error.message;
  return "The feed could not be imported.";
}

async function runOne(definition: Definition, deps: FeedDeps): Promise<FeedResult> {
  const base = {
    feed: definition.id,
    group: definition.group,
    fetched: 0,
    created: 0,
    updated: 0,
    untouched: 0,
    skipped: 0,
  } as const;
  const signal = AbortSignal.timeout(FEED_TIMEOUT_MS);
  try {
    if (definition.id === "cisa_kev") {
      const body = await deps.fetchJson(definition, signal);
      const records = parseKevCatalog(body);
      if (body === null || records.length === 0) {
        throw new ProviderError("bad_response", "The feed had no usable entries.");
      }
      const summary = await deps.recordVulnerabilities(records);
      return { ...base, status: "ok", fetched: records.length, ...summary };
    }

    const now = deps.now();
    let records: ExternalIndicatorRecord[];
    if (definition.id === "urlhaus") {
      const text = await deps.fetchText(definition, signal);
      records = text === null ? [] : parseUrlhausText(text, now);
    } else {
      const body = await deps.fetchJson(definition, signal);
      records =
        definition.id === "feodo" ? parseFeodoJson(body, now) : parseThreatFoxJson(body, now);
    }
    if (records.length === 0) {
      throw new ProviderError("bad_response", "The feed had no usable entries.");
    }
    const summary = await deps.recordIndicators(definition.id, records);
    return { ...base, status: "ok", fetched: records.length, ...summary };
  } catch (error) {
    if (error instanceof ProviderError) {
      logWarn("feeds.feed_failed", { feed: definition.id, reason: error.reason });
    } else {
      logError("feeds.feed_error", error, { feed: definition.id });
    }
    return { ...base, status: "failed", error: reasonOf(error) };
  }
}

/**
 * Runs the given groups (all of them by default). `actor` is the administrator who asked;
 * the run is audited once.
 */
export async function runFeedImport(
  options: { groups?: readonly FeedGroup[]; actor: string; request?: { headers: Headers } },
  deps: FeedDeps = defaultFeedDeps(),
  audit: typeof writeAuditLog = writeAuditLog,
): Promise<FeedResult[]> {
  const wanted = new Set(options.groups ?? FEED_GROUPS);
  const enabled = await deps.enabledGroups();

  const results = await Promise.all(
    FEEDS.filter((definition) => wanted.has(definition.group)).map(
      async (definition): Promise<FeedResult> => {
        if (!enabled.has(definition.group)) {
          return {
            feed: definition.id,
            group: definition.group,
            status: "disabled",
            fetched: 0,
            created: 0,
            updated: 0,
            untouched: 0,
            skipped: 0,
          };
        }
        return runOne(definition, deps);
      },
    ),
  );

  for (const group of FEED_GROUPS) {
    if (results.some((result) => result.group === group && result.status === "ok")) {
      await deps
        .markSynced(group)
        .catch((error) => logError("feeds.mark_synced", error, { group }));
    }
  }

  await audit(
    {
      action: "feeds.imported",
      userId: options.actor,
      entityType: "integration",
      entityId: "feeds",
      metadata: {
        trigger: "manual",
        results: results.map((r) => ({
          feed: r.feed,
          status: r.status,
          fetched: r.fetched,
          created: r.created,
          updated: r.updated,
        })),
      },
    },
    options.request,
  );

  return results;
}
