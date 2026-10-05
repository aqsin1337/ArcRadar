import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { DATA_ORIGINS, SEVERITIES } from "@/lib/indicators/constants";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import { ASSET_SORT_FIELDS, EVENT_SORT_FIELDS } from "./constants";

const source = blankToUndefined(z.string().trim().min(1).max(100));
const origin = blankToUndefined(z.enum(DATA_ORIGINS));

/** Query string of GET /api/events and of the /telemetry page. */
export const eventListQuerySchema = paginationQuerySchema.extend({
  source,
  severity: blankToUndefined(z.enum(SEVERITIES)),
  origin,
  asset: blankToUndefined(z.uuid({ error: "The asset id is not valid." })),
  sort: z.enum(EVENT_SORT_FIELDS).default("occurred_at"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

/** Query string of GET /api/assets. */
export const assetListQuerySchema = paginationQuerySchema.extend({
  source,
  origin,
  sort: z.enum(ASSET_SORT_FIELDS).default("last_seen"),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type EventListQuery = z.output<typeof eventListQuerySchema>;
export type AssetListQuery = z.output<typeof assetListQuerySchema>;

/** The page's query from its `searchParams`; a hand-edited address falls back to the defaults. */
export const parseEventListParams = (params: RawParams) =>
  parseListParams(eventListQuerySchema, params);
