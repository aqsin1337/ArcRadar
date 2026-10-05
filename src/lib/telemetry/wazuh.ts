import { z } from "zod";
import type { Severity } from "@/types/domain";
import {
  ALERT_MIN_LEVEL,
  MAX_BATCH,
  MAX_DESCRIPTION_LENGTH,
  MAX_TITLE_LENGTH,
  SEVERITY_BY_LEVEL,
} from "./constants";
import { extractIndicators } from "./extract";
import { boundPayload, clip, cleanText } from "./sanitize";
import type { NormalizedRecord, ParsedBatch, Rejection, TelemetrySource } from "./types";

/*
 * The Wazuh adapter. The Manager's integration script POSTs `{ "alerts": [ <alert>, ... ] }`, where
 * every alert is the JSON Wazuh wrote (rule, agent, manager, decoder, location, data, full_log).
 * Only what ArcRadar needs is read and validated; every other field is kept untouched in the bounded
 * raw copy on the event. An alert that cannot be used is rejected on its own with a reason: it never
 * fails the batch (a malformed alert in a retry spool must not block the ones behind it).
 */

/** Body of POST /api/ingest/wazuh. */
export const wazuhBatchSchema = z.strictObject({
  alerts: z
    .array(z.unknown())
    .min(1, "Send at least one alert.")
    .max(MAX_BATCH, `Send at most ${MAX_BATCH} alerts per request.`),
});

const stringOrNumber = z.union([z.string(), z.number()]);

const wazuhAlertSchema = z.looseObject({
  id: stringOrNumber,
  timestamp: z.string(),
  rule: z.looseObject({
    id: stringOrNumber,
    level: stringOrNumber,
    description: z.string().optional(),
    groups: z.array(z.string()).optional(),
    mitre: z.looseObject({ id: z.union([z.array(z.string()), z.string()]).optional() }).optional(),
  }),
  agent: z
    .looseObject({
      id: stringOrNumber,
      name: z.string().optional(),
      ip: z.string().optional(),
    })
    .optional(),
  manager: z.looseObject({ name: z.string().optional() }).optional(),
  location: z.string().optional(),
});

/** Wazuh rule level (0-15) to a severity: 0-3 info, 4-6 low, 7-9 medium, 10-12 high, 13-15 critical. */
export function severityForLevel(level: number): Severity {
  return (SEVERITY_BY_LEVEL.find((band) => level <= band.max) ?? SEVERITY_BY_LEVEL.at(-1)!)
    .severity;
}

/** Wazuh writes offsets without a colon ("...789+0000"); this accepts that and standard ISO 8601. */
export function parseWazuhTimestamp(value: string): string | null {
  const text = value.trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(text)) return null;
  const time = Date.parse(text);
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

const isRejection = (value: NormalizedRecord | Rejection): value is Rejection => "reason" in value;

const TECHNIQUE = /^T[0-9]{4}(\.[0-9]{3})?$/;

function techniqueIds(mitre: { id?: string | string[] } | undefined): string[] {
  const raw = mitre?.id === undefined ? [] : Array.isArray(mitre.id) ? mitre.id : [mitre.id];
  return [
    ...new Set(raw.map((id) => id.trim().toUpperCase()).filter((id) => TECHNIQUE.test(id))),
  ].slice(0, 20);
}

const IP = z.union([z.ipv4(), z.ipv6()]);

/** What kind of event this is, for the list and for grouping: Sysmon event id, file integrity, or the rule's last group. */
function eventTypeOf(alert: Record<string, unknown>, groups: string[]): string {
  const win = (alert.data as { win?: { system?: Record<string, unknown> } } | undefined)?.win;
  const provider = String(win?.system?.providerName ?? "");
  if (/sysmon/i.test(provider) && win?.system?.eventID !== undefined) {
    return `sysmon_event_${String(win.system.eventID).replace(/\D/g, "") || "unknown"}`;
  }
  if (alert.syscheck !== undefined) return "file_integrity";
  const last = groups.at(-1);
  const type = (last ?? "wazuh_alert")
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "_")
    .slice(0, 100);
  return type || "wazuh_alert";
}

function describe(input: {
  ruleId: string;
  level: number;
  agentName: string | null;
  agentIp: string | null;
  location: string | undefined;
  groups: string[];
  techniques: string[];
}): string {
  const parts = [`Wazuh rule ${input.ruleId} (level ${input.level})`];
  if (input.agentName)
    parts[0] += ` on ${input.agentName}${input.agentIp ? ` (${input.agentIp})` : ""}`;
  parts[0] += ".";
  if (input.location) parts.push(`Location: ${input.location}.`);
  if (input.groups.length > 0) parts.push(`Groups: ${input.groups.join(", ")}.`);
  if (input.techniques.length > 0) parts.push(`MITRE ATT&CK: ${input.techniques.join(", ")}.`);
  return clip(parts.join(" "), MAX_DESCRIPTION_LENGTH);
}

const PAYLOAD_KEYS = [
  "id",
  "timestamp",
  "rule",
  "agent",
  "manager",
  "decoder",
  "location",
  "data",
  "syscheck",
  "full_log",
] as const;

/** One Wazuh alert as a record for `ingest_telemetry()`, or the reason it cannot be used. */
export function normalizeWazuhAlert(raw: unknown, index: number): NormalizedRecord | Rejection {
  const parsed = wazuhAlertSchema.safeParse(raw);
  if (!parsed.success) {
    const field = parsed.error.issues[0]?.path.join(".") || "the alert";
    return { index, reason: `Not a Wazuh alert: ${field} is missing or has the wrong type.` };
  }
  const alert = parsed.data as Record<string, unknown> & z.output<typeof wazuhAlertSchema>;

  const level = Number(alert.rule.level);
  if (!Number.isInteger(level) || level < 0 || level > 15) {
    return { index, reason: "The rule level is not a whole number from 0 to 15." };
  }
  const occurred = parseWazuhTimestamp(alert.timestamp);
  if (!occurred) return { index, reason: "The timestamp is not a valid date and time." };

  const alertId = cleanText(String(alert.id)).trim();
  const managerName = alert.manager?.name ? cleanText(alert.manager.name).trim() : "";
  const sourceEventId = managerName ? `${managerName}:${alertId}` : alertId;
  if (alertId === "" || sourceEventId.length > 200) {
    return { index, reason: "The alert id is empty or too long." };
  }

  const ruleId = cleanText(String(alert.rule.id)).trim();
  const groups = (alert.rule.groups ?? [])
    .map((group) => clip(group, 60))
    .filter(Boolean)
    .slice(0, 20);
  const techniques = techniqueIds(alert.rule.mitre);
  const severity = severityForLevel(level);

  const agentId = alert.agent ? cleanText(String(alert.agent.id)).trim() : "";
  const agentName = alert.agent ? clip(alert.agent.name ?? `Agent ${agentId}`, 200) : null;
  const agentIp = alert.agent?.ip && IP.safeParse(alert.agent.ip).success ? alert.agent.ip : null;
  const hasWindowsData =
    typeof alert.data === "object" && alert.data !== null && "win" in (alert.data as object);
  const asset =
    alert.agent && agentId !== "" && agentId.length <= 100
      ? {
          external_id: agentId,
          name: agentName || `Agent ${agentId}`,
          ip_address: agentIp,
          os: hasWindowsData ? "Windows" : null,
        }
      : null;

  const create = level >= ALERT_MIN_LEVEL;
  const payload = Object.fromEntries(
    PAYLOAD_KEYS.filter((key) => alert[key] !== undefined).map((key) => [key, alert[key]]),
  );

  return {
    source_event_id: sourceEventId,
    occurred_at: occurred,
    event_type: eventTypeOf(alert, groups),
    title:
      clip(alert.rule.description ?? `Wazuh rule ${ruleId}`, MAX_TITLE_LENGTH) ||
      `Wazuh rule ${ruleId}`,
    description: describe({
      ruleId,
      level,
      agentName,
      agentIp,
      location: alert.location ? clip(alert.location, 200) : undefined,
      groups,
      techniques,
    }),
    severity,
    payload: boundPayload(payload),
    asset,
    alert: { create, technique_ids: techniques },
    // Indicators only come from alerts worth a person's attention; low-level noise stays an event.
    indicators: create ? extractIndicators(alert) : [],
  };
}

export const wazuhSource: TelemetrySource = {
  id: "wazuh",
  name: "Wazuh",
  parse(items): ParsedBatch {
    const records: NormalizedRecord[] = [];
    const rejected: Rejection[] = [];
    items.forEach((item, index) => {
      const result = normalizeWazuhAlert(item, index);
      if (isRejection(result)) rejected.push(result);
      else records.push(result);
    });
    return { records, rejected };
  },
};
