import { z } from "zod";

export type RawParams = Record<string, string | string[] | undefined>;

/** Form fields and query strings arrive as "" when left empty; treat that as "not set". */
export const blankToUndefined = <T extends z.ZodType>(schema: T) =>
  z.preprocess((value) => (value === "" ? undefined : value), schema.optional());

/** A page's `searchParams` with repeated keys reduced to their first value. */
export function firstValues(params: RawParams): Record<string, string | undefined> {
  return Object.fromEntries(
    Object.entries(params).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value]),
  );
}

/**
 * For list pages, where a hand-edited URL must never crash the page: invalid parameters fall back
 * to the schema's defaults and the caller is told, so it can say so.
 */
export function parseListParams<S extends z.ZodType>(
  schema: S,
  params: RawParams,
): { query: z.output<S>; ignoredInvalid: boolean } {
  const parsed = schema.safeParse(firstValues(params));
  if (parsed.success) return { query: parsed.data, ignoredInvalid: false };
  return { query: schema.parse({}), ignoredInvalid: true };
}
