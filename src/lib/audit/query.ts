import { z } from "zod";
import { paginationQuerySchema } from "@/lib/api/pagination";

/** Filters for GET /api/audit-logs (newest first). */
export const auditLogQuerySchema = paginationQuerySchema.extend({
  action: z
    .string()
    .max(100)
    .regex(/^[a-z_]+(\.[a-z_]+)*$/)
    .optional(),
  user_id: z.uuid().optional(),
  entity_type: z.string().min(1).max(100).optional(),
  entity_id: z.string().min(1).max(200).optional(),
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
});

export type AuditLogQuery = z.output<typeof auditLogQuerySchema>;
