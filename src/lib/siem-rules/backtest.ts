import { createHash } from "node:crypto";
import { z } from "zod";
import { RULE_KEY_PATTERN } from "./constants";

/*
 * Backtests: the SIEM host runs a rule's search over past data (the last 24 hours and 7 days) and reports what
 * it found, so a person sees "this would have fired N times" before the rule goes live. These are the pure
 * parts (the request schema and the comparison of what was tested with what the rule is now); the database
 * access is in ./backtest-repository.ts.
 */

export const BACKTEST_WINDOWS = [24, 168] as const;

const sampleItem = z.strictObject({
  time: z.string().max(40).optional(),
  count: z.number().int().min(0).max(1_000_000_000).optional(),
  group: z
    .record(z.string().max(80), z.union([z.string().max(200), z.number()]))
    .refine((group) => Object.keys(group).length <= 6, "At most 6 group fields.")
    .optional(),
});

/** Body of POST /api/ingest/splunk/backtests. */
export const backtestBatchSchema = z.strictObject({
  results: z
    .array(
      z.strictObject({
        rule_key: z.string().regex(RULE_KEY_PATTERN, "Not a valid rule key."),
        window_hours: z.union([z.literal(24), z.literal(168)]),
        kind: z.enum(["threshold", "events"]),
        matches: z.number().int().min(0).max(1_000_000_000),
        scanned: z.number().int().min(0).max(1_000_000_000).optional(),
        sample: z.array(sampleItem).max(5).default([]),
        search_sha256: z.string().regex(/^[0-9a-f]{64}$/, "Not a SHA-256 digest."),
        error: z.string().max(300).optional(),
      }),
    )
    .min(1, "Send at least one result.")
    .max(200, "Send at most 200 results per request."),
});

export type BacktestBatch = z.output<typeof backtestBatchSchema>;

export const sha256Hex = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

/** The value of the `search = ` line of a rendered rule file. */
export function searchLineOf(content: string): string | null {
  const line = content.split("\n").find((candidate) => candidate.startsWith("search = "));
  return line ? line.slice("search = ".length) : null;
}

/** The digest a backtest of this rule's current file should carry; a result with another digest is out of date. */
export function expectedSearchDigest(content: string): string | null {
  const search = searchLineOf(content);
  return search === null ? null : sha256Hex(search);
}
