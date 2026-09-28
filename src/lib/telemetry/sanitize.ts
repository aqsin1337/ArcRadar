import { MAX_PAYLOAD_BYTES } from "./constants";

/**
 * Text from a sensor is stored as it came, minus what the database cannot hold: the NUL character
 * (Postgres refuses it in text and in jsonb) and lone surrogates (jsonb refuses those too).
 */
export function cleanText(value: string): string {
  return value.replaceAll("\u0000", "").toWellFormed();
}

/** Cuts a string to `max` characters, ending in an ellipsis when it was longer. */
export function clip(value: string, max: number): string {
  const text = cleanText(value).trim();
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** A copy of any JSON value with every string cleaned (see `cleanText`). */
export function cleanJson(value: unknown): unknown {
  if (typeof value === "string") return cleanText(value);
  if (Array.isArray(value)) return value.map(cleanJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        cleanText(key),
        cleanJson(entry),
      ]),
    );
  }
  return value;
}

const byteLength = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

/**
 * Keeps the raw alert on an event within `MAX_PAYLOAD_BYTES`: the raw log line is dropped first, then
 * the decoded `data`, then everything but the rule. A cut is marked (`truncated`), never silent.
 */
export function boundPayload(
  payload: Record<string, unknown>,
  max = MAX_PAYLOAD_BYTES,
): Record<string, unknown> {
  const clean = cleanJson(payload) as Record<string, unknown>;
  if (byteLength(clean) <= max) return clean;

  const withoutLog = Object.entries(clean).filter(([key]) => key !== "full_log");
  const cut: Record<string, unknown> = {
    ...Object.fromEntries(withoutLog),
    truncated: ["full_log"],
  };
  if (byteLength(cut) <= max) return cut;

  cut.data = { truncated: true };
  cut.truncated = ["full_log", "data"];
  if (byteLength(cut) <= max) return cut;

  const rule = clean.rule;
  return {
    id: clean.id,
    timestamp: clean.timestamp,
    rule: rule && typeof rule === "object" ? pickRule(rule as Record<string, unknown>) : undefined,
    truncated: ["everything but the rule"],
  };
}

function pickRule(rule: Record<string, unknown>) {
  return { id: rule.id, level: rule.level, description: rule.description };
}
