import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { auditLogQuerySchema } from "@/lib/audit/query";
import { listAuditLogs } from "@/lib/audit/service";

export const dynamic = "force-dynamic";

/** GET /api/audit-logs?page&page_size&action&user_id&entity_type&entity_id&from&to (audit:read). */
export const GET = protectedRoute({ permissions: ["audit:read"] }, async ({ request, auth }) => {
  const query = parseQuery(request, auditLogQuerySchema);
  return ok(await listAuditLogs(auth.supabase, query));
});
