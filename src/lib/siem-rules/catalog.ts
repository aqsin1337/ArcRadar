import { z } from "zod";

/*
 * The field catalog: which fields a SIEM really holds, as the SIEM host reported them. These are the
 * pure parts (types, the request schema, lookups, the AI summary); the database access is in
 * ./catalog-repository.ts.
 */

export type CatalogField = {
  name: string;
  /** Events, out of `events_sampled`, that carried the field. */
  events_with_field: number;
  distinct_values: number | null;
  sample_values: string[];
};

export type CatalogSource = {
  index: string;
  sourcetype: string;
  events_sampled: number;
  window_hours: number;
  reported_at: string;
  fields: CatalogField[];
};

export type FieldCatalog = { sources: CatalogSource[] };

export const EMPTY_CATALOG: FieldCatalog = { sources: [] };

const INDEX_PATTERN = /^[a-z0-9_][a-z0-9_-]{0,59}$/;
const SOURCETYPE_PATTERN = /^[A-Za-z0-9_:./-]{1,80}$/;

/** Body of POST /api/ingest/splunk/catalog. A field with a name the database refuses is skipped there, not fatal. */
export const catalogBatchSchema = z.strictObject({
  sources: z
    .array(
      z.strictObject({
        index: z.string().regex(INDEX_PATTERN, "Not a valid index name."),
        sourcetype: z.string().regex(SOURCETYPE_PATTERN, "Not a valid sourcetype."),
        window_hours: z.number().int().min(1).max(720),
        events_sampled: z.number().int().min(1).max(100_000_000),
        fields: z
          .array(
            z.strictObject({
              name: z.string().min(1).max(200),
              count: z.number().int().min(0).max(100_000_000),
              distinct: z.number().int().min(0).max(100_000_000).optional(),
              values: z.array(z.string().max(500)).max(20).optional(),
            }),
          )
          .max(500),
      }),
    )
    .min(1, "Send at least one source.")
    .max(50, "Send at most 50 sources per request."),
});

export type CatalogBatch = z.output<typeof catalogBatchSchema>;

/** The sources a rule on `index` (and `sourcetype`, when it names one) draws from. */
export function sourcesFor(
  catalog: FieldCatalog,
  index: string,
  sourcetype: string | null,
): CatalogSource[] {
  return catalog.sources.filter(
    (source) => source.index === index && (!sourcetype || source.sourcetype === sourcetype),
  );
}

/** How often a field appears among a source's events, 0 to 100. */
export const fieldPercent = (field: CatalogField, source: CatalogSource) =>
  Math.round((100 * field.events_with_field) / Math.max(1, source.events_sampled));

/**
 * What the AI is told about the data. Only field names that exist may be used in a rule, so the
 * model sees the real ones, a few example values each, bounded in size.
 */
export function summarizeCatalog(catalog: FieldCatalog): string {
  const lines: string[] = [];
  for (const source of catalog.sources.slice(0, 6)) {
    const fields = source.fields
      .slice(0, 40)
      .map((field) => {
        const examples = field.sample_values
          .slice(0, 3)
          .map((value) => value.replace(/\s+/g, " ").trim().slice(0, 30))
          .join(", ");
        return examples ? `${field.name} [${examples}]` : field.name;
      })
      .join("; ");
    lines.push(
      `- index=${source.index} sourcetype=${source.sourcetype} (${source.events_sampled} events sampled over ${source.window_hours} h): ${fields}`,
    );
  }
  return lines.join("\n").slice(0, 6000);
}

export type FieldOption = { name: string; percent: number; examples: string[] };

/**
 * The fields to offer for a rule on `index` (and `sourcetype`): every field of the matching sources,
 * merged by name, the most common first, with how often it appears and a few example values.
 */
export function fieldOptions(
  catalog: FieldCatalog,
  index: string,
  sourcetype: string | null,
): FieldOption[] {
  const merged = new Map<string, FieldOption>();
  for (const source of sourcesFor(catalog, index, sourcetype)) {
    for (const field of source.fields) {
      const percent = fieldPercent(field, source);
      const current = merged.get(field.name);
      if (!current) {
        merged.set(field.name, {
          name: field.name,
          percent,
          examples: field.sample_values.slice(0, 5),
        });
      } else {
        current.percent = Math.max(current.percent, percent);
        for (const value of field.sample_values) {
          if (current.examples.length < 5 && !current.examples.includes(value)) {
            current.examples.push(value);
          }
        }
      }
    }
  }
  return [...merged.values()].sort((a, b) => b.percent - a.percent || a.name.localeCompare(b.name));
}
