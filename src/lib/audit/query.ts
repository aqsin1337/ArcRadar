import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";
import { blankToUndefined, parseListParams, type RawParams } from "@/lib/validation/query";
import { createListUrl } from "@/lib/validation/list-url";

/** Filters for GET /api/audit-logs (newest first). An empty value ("cleared" in the UI) means "no
 * filter", same as leaving the field out entirely. */
export const auditLogQuerySchema = paginationQuerySchema.extend({
  action: blankToUndefined(
    z
      .string()
      .max(100)
      .regex(/^[a-z_]+(\.[a-z_]+)*$/),
  ),
  user_id: blankToUndefined(z.uuid()),
  entity_type: blankToUndefined(z.string().min(1).max(100)),
  entity_id: blankToUndefined(z.string().min(1).max(200)),
  from: blankToUndefined(z.iso.datetime({ offset: true })),
  to: blankToUndefined(z.iso.datetime({ offset: true })),
});

export type AuditLogQuery = z.output<typeof auditLogQuerySchema>;

/** The audit log page's query from its `searchParams`; a hand-edited address falls back to the defaults. */
export const parseAuditLogListParams = (params: RawParams) =>
  parseListParams(auditLogQuerySchema, params);

export const auditLogList = createListUrl({
  path: "/audit-log",
  filterKeys: ["action", "user_id", "entity_type", "entity_id", "from", "to"],
  defaultSort: "created_at",
});
