import { z } from "zod";
import { SEVERITIES } from "@/lib/indicators/constants";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";

/** How far back the activity chart and the "recent" panels look, and an optional severity focus. */
export const dashboardQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).default(14),
  severity: blankToUndefined(z.enum(SEVERITIES)),
});

export type DashboardQuery = z.output<typeof dashboardQuerySchema>;

/** The dashboard's query from its `searchParams`; a hand-edited address falls back to the defaults. */
export const parseDashboardParams = (params: RawParams) =>
  parseListParams(dashboardQuerySchema, params);
