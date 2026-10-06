/** A Wazuh alert of this rule level or higher becomes an ArcRadar alert (lower ones are kept as events only). */
export const ALERT_MIN_LEVEL = 7;

/** Alerts accepted in one request. The Manager sends one at a time; a retry spool sends a few together. */
export const MAX_BATCH = 100;

/** Largest request body of an ingest endpoint (far below Vercel's 4.5 MB request limit). */
export const MAX_BODY_BYTES = 1024 * 1024;

/** The raw alert kept on an event is cut down to this size (the raw log line goes first). */
export const MAX_PAYLOAD_BYTES = 16 * 1024;

/** Indicators taken from one alert. */
export const MAX_INDICATORS_PER_ALERT = 5;

export const MAX_TITLE_LENGTH = 300;
export const MAX_DESCRIPTION_LENGTH = 1000;

/** A source that delivered something this recently is "receiving"; after that it is "quiet". */
export const RECEIVING_WITHIN_MINUTES = 15;

/** The telemetry sources ArcRadar knows how to receive, shown even before their first event. */
export const TELEMETRY_SOURCES = [
  { id: "wazuh", name: "Wazuh" },
  { id: "splunk", name: "Splunk" },
] as const;
export type TelemetrySourceId = (typeof TELEMETRY_SOURCES)[number]["id"];

/** Wazuh rule levels are 0-15. */
export const SEVERITY_BY_LEVEL: readonly {
  max: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
}[] = [
  { max: 3, severity: "info" },
  { max: 6, severity: "low" },
  { max: 9, severity: "medium" },
  { max: 12, severity: "high" },
  { max: 15, severity: "critical" },
];

export const EVENT_SORT_FIELDS = ["occurred_at", "created_at", "severity"] as const;
export const ASSET_SORT_FIELDS = ["last_seen", "name", "first_seen"] as const;
