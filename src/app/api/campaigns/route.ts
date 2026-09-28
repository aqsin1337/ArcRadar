import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody, parseQuery } from "@/lib/api/validate";
import { campaignListQuerySchema, createCampaignSchema } from "@/lib/threat-intel/schema";
import { createCampaign, listCampaigns } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/campaigns?q&status&origin&sort&order&page&page_size
 * Text search (name and description), filters, sorting and pagination, with the number of linked
 * actors and indicators per campaign. Needs threat_intel:read.
 */
export const GET = protectedRoute(
  { permissions: ["threat_intel:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, campaignListQuerySchema);
    return ok(await listCampaigns(auth.supabase, query));
  },
);

/**
 * POST /api/campaigns  { name, description?, status?, first_seen?, last_seen?, actor_ids? }
 * Creates a local campaign (needs threat_intel:write). Origin and owner are not accepted from the client.
 */
export const POST = protectedRoute(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createCampaignSchema);
    return ok(await createCampaign(auth, input, request), { status: 201 });
  },
);
