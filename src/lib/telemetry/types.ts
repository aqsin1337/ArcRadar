import type {
  Alert,
  Asset,
  DataOrigin,
  IndicatorType,
  SecurityEvent,
  Severity,
} from "@/types/domain";

/** One record of a batch, in the shape `ingest_telemetry()` expects. */
export type NormalizedRecord = {
  source_event_id: string;
  /** ISO timestamp in UTC. */
  occurred_at: string;
  event_type: string;
  title: string;
  description: string | null;
  severity: Severity;
  /** The raw alert, cut down to a bounded size. */
  payload: Record<string, unknown>;
  asset: { external_id: string; name: string; ip_address: string | null; os: string | null } | null;
  alert: { create: boolean; technique_ids: string[] };
  /** In priority order: the first one the database accepts becomes the alert's indicator. */
  indicators: { type: IndicatorType; value: string }[];
};

/** A record of the request that could not be used, and why (never the submitted values). */
export type Rejection = { index: number; reason: string };

export type ParsedBatch = { records: NormalizedRecord[]; rejected: Rejection[] };

/**
 * A source of inbound telemetry (the counterpart of `IntelProvider`, which looks things up going
 * out). It turns what a sensor sent into normalized records; it never touches the database.
 */
export interface TelemetrySource {
  readonly id: string;
  readonly name: string;
  /** Normalizes each record of a request. A bad record is rejected on its own, never fatal. */
  parse(items: readonly unknown[]): ParsedBatch;
}

/** What `ingest_telemetry()` reports. */
export type IngestSummary = {
  events_created: number;
  alerts_created: number;
  duplicates: number;
  assets_created: number;
  indicators_created: number;
};

export type IngestResult = IngestSummary & { received: number; rejected: Rejection[] };

export type SourceHealth = {
  source: string;
  origin: DataOrigin;
  last_event_at: string | null;
  last_received_at: string | null;
  events_total: number;
  events_24h: number;
  alerts_total: number;
  assets_total: number;
};

export type AssetListItem = Asset;

export type EventListItem = Pick<
  SecurityEvent,
  | "id"
  | "event_type"
  | "title"
  | "severity"
  | "source"
  | "origin"
  | "occurred_at"
  | "created_at"
  | "asset_id"
  | "indicator_id"
> & {
  asset: { id: string; name: string } | null;
  /** The alert raised from this event, when there is one. */
  alert_id: string | null;
};

export type AlertAsset = Pick<Alert, "asset_id"> & {
  asset: Pick<Asset, "id" | "name" | "ip_address" | "os"> | null;
};
