import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import { REPORT_TYPES } from "./constants";

const title = z
  .string()
  .trim()
  .min(1, "Enter a title.")
  .max(300, "The title can have at most 300 characters.")
  .optional();

const uuid = (what: string) => z.uuid({ error: `The ${what} id is not valid.` });

/**
 * Body of POST /api/reports. A title is optional (the service fills in a reasonable default); the
 * fields a type needs are required only for that type, so a client cannot ask for an investigation
 * report without naming the investigation. The workspace-wide types (indicators, alerts,
 * vulnerabilities) summarize the current state, like the dashboard; they take no date range.
 */
export const createReportSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("investigation"),
    title,
    investigation_id: uuid("investigation"),
  }),
  z.strictObject({ type: z.literal("indicators"), title }),
  z.strictObject({ type: z.literal("alerts"), title }),
  z.strictObject({ type: z.literal("vulnerabilities"), title }),
]);

export type CreateReportInput = z.output<typeof createReportSchema>;

export const reportListQuerySchema = paginationQuerySchema.extend({
  q: blankToUndefined(z.string().trim().max(200, "The search text is too long.")),
  type: blankToUndefined(z.enum(REPORT_TYPES)),
});

export type ReportListQuery = z.output<typeof reportListQuerySchema>;

export const parseReportListParams = (params: RawParams) =>
  parseListParams(reportListQuerySchema, params);

export const reportIdSchema = z.uuid({ error: "The report id is not valid." });
