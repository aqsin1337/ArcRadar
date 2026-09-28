import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import { actorListQuerySchema, createActorSchema } from "@/lib/threat-intel/schema";
import { createActor, listActors } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/threat-actors?q&origin&sort&order&page&page_size
 * Text search (all terms must match the name, aliases, description, motivation, country, industries or
 * target countries), origin filter, sorting and pagination, with the number of linked malware,
 * campaigns, techniques and indicators per actor. Needs threat_intel:read.
 */
export const GET = protectedRoute(
  { permissions: ["threat_intel:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, actorListQuerySchema);
    return ok(await listActors(auth.supabase, query));
  },
);

/**
 * POST /api/threat-actors  { name, aliases?, description?, motivation?, attribution_country?,
 * target_industries?, target_countries?, first_seen?, last_seen?, malware_ids?, campaign_ids?, technique_ids? }
 * Creates a local threat actor (needs threat_intel:write). Origin and owner are not accepted from the
 * client. Link lists replace nothing on create; they set the initial links.
 */
export const POST = protectedRoute(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createActorSchema);
    return ok(await createActor(auth, input, request), { status: 201 });
  },
);
