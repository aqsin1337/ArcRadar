import type { Json } from "@/types/database";

const SENSITIVE_KEY =
  /pass(word|wd)?|secret|token|authorization|cookie|credential|api[_-]?key|key_hash/i;
const MAX_DEPTH = 4;
const MAX_STRING_LENGTH = 500;
const MAX_ARRAY_ITEMS = 50;
const MAX_SERIALIZED_BYTES = 8 * 1024;
export const REDACTED = "[redacted]";

function sanitizeValue(value: unknown, depth: number): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    return value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}…` : value;
  }
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "boolean") return value;
  if (depth >= MAX_DEPTH) return "[truncated]";
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitizeValue(item, depth + 1));
  }
  if (typeof value === "object") {
    const result: { [key: string]: Json } = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = SENSITIVE_KEY.test(key) ? REDACTED : sanitizeValue(item, depth + 1);
    }
    return result;
  }
  return String(value);
}

/**
 * Audit metadata is stored forever and readable by admins, so it is scrubbed before it is written:
 * secret-looking keys are redacted, strings and arrays are capped, nesting is limited and the whole
 * document has a size ceiling.
 */
export function sanitizeMetadata(metadata: Record<string, unknown> | undefined): {
  [key: string]: Json;
} {
  if (!metadata) return {};
  const clean = sanitizeValue(metadata, 0) as { [key: string]: Json };
  return JSON.stringify(clean).length > MAX_SERIALIZED_BYTES ? { truncated: true } : clean;
}
