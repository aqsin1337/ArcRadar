import "server-only";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient } from "@/lib/auth/context";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import { buildSourceCards, type SourceCard } from "./health";
import { findAssets, findEvents, findSourceHealth, ingestRecords } from "./repository";
import type { AssetListQuery, EventListQuery } from "./schema";
import type {
  AssetListItem,
  EventListItem,
  IngestResult,
  IngestSummary,
  TelemetrySource,
} from "./types";

type RequestLike = { headers: Headers };

const NOTHING: IngestSummary = {
  events_created: 0,
  alerts_created: 0,
  duplicates: 0,
  assets_created: 0,
  indicators_created: 0,
};

export type IngestDeps = {
  store: typeof ingestRecords;
  audit: typeof writeAuditLog;
};

const defaultDeps = (): IngestDeps => ({ store: ingestRecords, audit: writeAuditLog });

/**
 * Takes one request's worth of sensor alerts: normalizes each (a bad one is rejected on its own),
 * records the rest in one transaction, and audits the batch once (who sent it, how many of each
 * outcome; never the alerts themselves). The caller has already verified the API key.
 */
export async function ingestBatch(
  principal: ApiKeyPrincipal,
  source: TelemetrySource,
  items: readonly unknown[],
  request: RequestLike,
  deps: IngestDeps = defaultDeps(),
): Promise<IngestResult> {
  const { records, rejected } = source.parse(items);
  const summary = records.length > 0 ? await deps.store(source.id, records) : NOTHING;

  await deps.audit(
    {
      action: "ingest.batch",
      userId: null,
      entityType: "api_key",
      entityId: principal.keyId,
      metadata: {
        source: source.id,
        key_name: principal.keyName,
        key_prefix: principal.keyPrefix,
        owner_id: principal.ownerId,
        received: items.length,
        accepted: records.length,
        rejected: rejected.length,
        ...summary,
      },
    },
    request,
  );
  return { received: items.length, ...summary, rejected };
}

/** Every source that has delivered, plus the connectors ArcRadar can receive from, with their status. */
export async function getSourceCards(
  supabase: AuthClient,
  now = new Date(),
): Promise<SourceCard[]> {
  return buildSourceCards(await findSourceHealth(supabase), now);
}

export async function listAssets(
  supabase: AuthClient,
  query: AssetListQuery,
): Promise<Page<AssetListItem>> {
  const { rows, total } = await findAssets(supabase, query);
  return buildPage(rows, total, query);
}

export async function listEvents(
  supabase: AuthClient,
  query: EventListQuery,
): Promise<Page<EventListItem>> {
  const { rows, total } = await findEvents(supabase, query);
  return buildPage(rows, total, query);
}
