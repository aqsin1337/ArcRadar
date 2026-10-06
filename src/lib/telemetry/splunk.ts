import { createHash } from "node:crypto";
import { z } from "zod";
import type { Severity } from "@/types/domain";
import {
  MAX_BATCH,
  MAX_DESCRIPTION_LENGTH,
  MAX_PAYLOAD_BYTES,
  MAX_TITLE_LENGTH,
} from "./constants";
import { extractIndicators } from "./extract";
import { cleanJson, clip } from "./sanitize";
import type { NormalizedRecord, ParsedBatch, Rejection, TelemetrySource } from "./types";

/*
 * The Splunk adapter. A saved search that ArcRadar wrote (see src/lib/siem-rules/dialects/splunk.ts)
 * carries the custom alert action `arcradar_forward`; on the Splunk host that action POSTs
 * `{ "alerts": [ <item>, ... ] }` where every item is
 *
 *   { sid, search_name, results_link?, server_host?, result: { <field>: <value>, ... },
 *     configuration?: { rule_key?, name?, severity?, mitre? } }
 *
 * `sid`, `search_name`, `results_link` and `result` are exactly what Splunk's own webhook action sends;
 * `configuration` is the action's parameters (the rule key, name, severity and MITRE ids ArcRadar put
 * in the saved search). Every item is already a triggered alert, so each one becomes an event AND an
 * alert. Like the Wazuh adapter, an unusable item is rejected on its own with a reason and never fails
 * the batch.
 */

/** Body of POST /api/ingest/splunk. */
export const splunkBatchSchema = z.strictObject({
  alerts: z
    .array(z.unknown())
    .min(1, "Send at least one alert.")
    .max(MAX_BATCH, `Send at most ${MAX_BATCH} alerts per request.`),
});

const splunkItemSchema = z.looseObject({
  sid: z.union([z.string(), z.number()]),
  search_name: z.string().min(1),
  results_link: z.string().optional(),
  server_host: z.string().optional(),
  result: z.record(z.string(), z.unknown()),
  configuration: z
    .looseObject({
      rule_key: z.string().optional(),
      name: z.string().optional(),
      severity: z.string().optional(),
      mitre: z.string().optional(),
    })
    .optional(),
});

const SEVERITIES = new Set<Severity>(["low", "medium", "high", "critical"]);
const TECHNIQUE = /^T[0-9]{4}(\.[0-9]{3})?$/;

/** Splunk's `_time` is epoch seconds ("1696579200.000") or, in an export, ISO 8601. */
export function parseSplunkTime(value: unknown): string | null {
  const text = typeof value === "number" ? String(value) : typeof value === "string" ? value : "";
  const trimmed = text.trim();
  if (/^\d{9,11}(\.\d+)?$/.test(trimmed)) {
    const date = new Date(Number(trimmed) * 1000);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(trimmed)) {
    return null;
  }
  const time = Date.parse(trimmed.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

const str = (value: unknown): string | null => {
  if (typeof value === "number") return String(value);
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
};

/** The first of several field names that holds a value (Splunk field names vary with the add-on). */
function firstOf(result: Record<string, unknown>, names: readonly string[]): string | null {
  for (const name of names) {
    const value = str(result[name]);
    if (value) return value;
  }
  return null;
}

/** A stable short digest of a result row, so two rows of one search run get different event ids. */
function digestOf(result: Record<string, unknown>): string {
  const sorted = Object.keys(result)
    .sort()
    .map((key) => [key, result[key]]);
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex").slice(0, 16);
}

/** The result's fields the shared indicator extractor knows, laid out the way it expects them. */
function indicatorSource(result: Record<string, unknown>): Record<string, unknown> {
  return {
    data: {
      dstip: firstOf(result, ["dest_ip", "dest", "DestinationIp", "DestAddress"]),
      srcip: firstOf(result, [
        "Source_Network_Address",
        "src_ip",
        "src",
        "IpAddress",
        "SourceIp",
        "ClientAddress",
      ]),
      sha256: firstOf(result, ["SHA256", "sha256", "file_hash_sha256"])?.toLowerCase(),
      sha1: firstOf(result, ["SHA1", "sha1"])?.toLowerCase(),
      md5: firstOf(result, ["MD5", "md5"])?.toLowerCase(),
      url: firstOf(result, ["url", "Url", "uri"]),
    },
  };
}

const encoder = new TextEncoder();
const bytes = (value: unknown) => encoder.encode(JSON.stringify(value)).length;

/** The raw item, cleaned and kept within `MAX_PAYLOAD_BYTES`: a long `result` is cut and marked, never silent. */
function boundSplunkPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const clean = cleanJson(payload) as Record<string, unknown>;
  if (bytes(clean) <= MAX_PAYLOAD_BYTES) return clean;
  const result = (clean.result ?? {}) as Record<string, unknown>;
  const kept: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(result).slice(0, 40)) {
    kept[key] = typeof value === "string" ? clip(value, 300) : value;
  }
  const cut = { ...clean, result: kept, truncated: ["result"] };
  if (bytes(cut) <= MAX_PAYLOAD_BYTES) return cut;
  return {
    sid: clean.sid,
    search_name: clean.search_name,
    truncated: ["result", "everything else"],
  };
}

const isRejection = (value: NormalizedRecord | Rejection): value is Rejection => "reason" in value;

/** One item from the Splunk alert action as a record for `ingest_telemetry()`, or the reason it cannot be used. */
export function normalizeSplunkAlert(raw: unknown, index: number): NormalizedRecord | Rejection {
  const parsed = splunkItemSchema.safeParse(raw);
  if (!parsed.success) {
    const field = parsed.error.issues[0]?.path.join(".") || "the alert";
    return { index, reason: `Not a Splunk alert: ${field} is missing or has the wrong type.` };
  }
  const item = parsed.data;

  const sid = clip(String(item.sid), 80);
  const searchName = clip(item.search_name, 80);
  if (sid === "" || searchName === "") return { index, reason: "The search id or name is empty." };
  const sourceEventId = `${searchName}:${sid}:${digestOf(item.result)}`;

  const config = item.configuration ?? {};
  const ruleKey = config.rule_key ? clip(config.rule_key, 60) : null;
  const severity = (
    SEVERITIES.has(config.severity as Severity) ? config.severity : "medium"
  ) as Severity;
  const techniques = [
    ...new Set(
      (config.mitre ?? "")
        .split(",")
        .map((id) => id.trim().toUpperCase())
        .filter((id) => TECHNIQUE.test(id)),
    ),
  ].slice(0, 20);

  const occurred = parseSplunkTime(item.result._time) ?? new Date().toISOString();
  const host = firstOf(item.result, ["host", "ComputerName", "Computer", "dest_host"]);
  const asset = host
    ? { external_id: clip(host, 100), name: clip(host, 200), ip_address: null, os: null }
    : null;

  const name = config.name ? clip(config.name, MAX_TITLE_LENGTH) : "";
  const title = name || clip(`Splunk alert ${searchName}`, MAX_TITLE_LENGTH);
  const description = clip(
    [
      `Splunk rule ${ruleKey ?? searchName} (${severity})${host ? ` on ${host}` : ""}.`,
      `Saved search: ${searchName}.`,
      techniques.length > 0 ? `MITRE ATT&CK: ${techniques.join(", ")}.` : "",
    ]
      .filter(Boolean)
      .join(" "),
    MAX_DESCRIPTION_LENGTH,
  );

  return {
    source_event_id: sourceEventId,
    occurred_at: occurred,
    event_type: "splunk_alert",
    title,
    description,
    severity,
    payload: boundSplunkPayload({
      sid,
      search_name: searchName,
      results_link: item.results_link,
      server_host: item.server_host,
      configuration: item.configuration,
      result: item.result,
    }),
    asset,
    alert: { create: true, technique_ids: techniques },
    indicators: extractIndicators(indicatorSource(item.result)),
  };
}

export const splunkSource: TelemetrySource = {
  id: "splunk",
  name: "Splunk",
  parse(items): ParsedBatch {
    const records: NormalizedRecord[] = [];
    const rejected: Rejection[] = [];
    items.forEach((item, index) => {
      const result = normalizeSplunkAlert(item, index);
      if (isRejection(result)) rejected.push(result);
      else records.push(result);
    });
    return { records, rejected };
  },
};
