import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { FEED_GROUPS, runFeedImport } from "@/lib/feeds/import";
import { userSubject } from "@/lib/rate-limit/service";

export const dynamic = "force-dynamic";
// Several public feeds are downloaded and stored in one request.
export const maxDuration = 120;

const bodySchema = z.strictObject({ groups: z.array(z.enum(FEED_GROUPS)).min(1).optional() });

/**
 * POST /api/feeds/import  { groups? }   (groups: abusech | cisa_kev, all by default)
 * Imports the public threat feeds now, abuse.ch (URLhaus,
 * Feodo Tracker, ThreatFox) as indicators and CISA's known-exploited list as vulnerabilities. A group
 * an administrator paused on the Integrations page is skipped. Needs integrations:manage.
 */
export const POST = protectedRoute(
  {
    permissions: ["integrations:manage"],
    rateLimit: { routeClass: "feedImportByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth }) => {
    const { groups } = await parseJsonBody(request, bodySchema);
    return ok(await runFeedImport({ groups, actor: auth.user.id, request }));
  },
);
