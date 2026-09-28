import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import { alertListQuerySchema, createAlertSchema } from "@/lib/alerts/schema";
import { createAlert, listAlerts } from "@/lib/alerts/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/alerts?q&status&severity&origin&source&assignee&sort&order&page&page_size
 * Text search (all terms must match the title, description, source or the linked indicator's value),
 * filters (`assignee` is `me`, `none` or a user id), sorting and pagination. Needs alerts:read.
 */
export const GET = protectedRoute({ permissions: ["alerts:read"] }, async ({ request, auth }) => {
  const query = parseQuery(request, alertListQuerySchema);
  return ok(await listAlerts(auth, query));
});

/**
 * POST /api/alerts  { title, description?, severity?, indicator_id? }
 * Creates a manual, local alert (needs alerts:write). Its source is `manual`; origin and owner are not
 * accepted from the client.
 */
export const POST = protectedRoute({ permissions: ["alerts:write"] }, async ({ request, auth }) => {
  const input = await parseJsonBody(request, createAlertSchema);
  return ok(await createAlert(auth, input, request), { status: 201 });
});
