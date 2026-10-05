import type { DataOrigin } from "@/types/domain";
import { RECEIVING_WITHIN_MINUTES, TELEMETRY_SOURCES } from "./constants";
import type { SourceHealth } from "./types";

/*
 * What ArcRadar can honestly say about a telemetry source: when something last arrived. It cannot
 * see the sensor itself, so it never says "connected" or "healthy": a source is receiving (something
 * arrived recently), quiet (nothing recently), or has never delivered. Demo feeds are sample data,
 * not a live connection, and are labelled as such.
 */
export type SourceStatus = "receiving" | "quiet" | "never" | "demo";

export type SourceCard = {
  id: string;
  name: string;
  origin: DataOrigin | null;
  status: SourceStatus;
  last_event_at: string | null;
  last_received_at: string | null;
  events_total: number;
  events_24h: number;
  alerts_total: number;
  assets_total: number;
};

export function statusOf(
  row: Pick<SourceHealth, "origin" | "last_received_at">,
  now: Date,
): SourceStatus {
  if (row.origin === "demo") return "demo";
  if (!row.last_received_at) return "never";
  const ageMs = now.getTime() - Date.parse(row.last_received_at);
  return ageMs <= RECEIVING_WITHIN_MINUTES * 60_000 ? "receiving" : "quiet";
}

const EMPTY = {
  last_event_at: null,
  last_received_at: null,
  events_total: 0,
  events_24h: 0,
  alerts_total: 0,
  assets_total: 0,
} as const;

/**
 * The connectors ArcRadar can receive from (always listed, even before their first event), then any
 * other live source that has delivered, then the demo feeds.
 */
export function buildSourceCards(rows: readonly SourceHealth[], now: Date): SourceCard[] {
  const known = TELEMETRY_SOURCES.map((connector): SourceCard => {
    const row = rows.find(
      (candidate) => candidate.source === connector.id && candidate.origin === "external",
    );
    return row
      ? {
          id: connector.id,
          name: connector.name,
          origin: "external",
          status: statusOf(row, now),
          ...pick(row),
        }
      : { id: connector.id, name: connector.name, origin: null, status: "never", ...EMPTY };
  });

  const knownIds = new Set<string>(TELEMETRY_SOURCES.map((connector) => connector.id));
  const others = rows
    .filter((row) => !(row.origin === "external" && knownIds.has(row.source)))
    .map((row): SourceCard => ({
      id: row.source,
      name: row.source,
      origin: row.origin,
      status: statusOf(row, now),
      ...pick(row),
    }))
    .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));

  return [...known, ...others];
}

const rank = (card: SourceCard) => (card.origin === "demo" ? 2 : card.origin === "local" ? 1 : 0);

const pick = (row: SourceHealth) => ({
  last_event_at: row.last_event_at,
  last_received_at: row.last_received_at,
  events_total: row.events_total,
  events_24h: row.events_24h,
  alerts_total: row.alerts_total,
  assets_total: row.assets_total,
});
