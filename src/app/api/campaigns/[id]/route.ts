import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateCampaignSchema } from "@/lib/threat-intel/schema";
import { deleteCampaign, getCampaign, updateCampaign } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/campaigns/:id — the campaign with its actors and indicators. */
export const GET = protectedRoute<Params>(
  { permissions: ["threat_intel:read"] },
  async ({ auth, params }) => ok(await getCampaign(auth.supabase, params.id)),
);

/** PATCH /api/campaigns/:id — needs threat_intel:write. `actor_ids` replaces the whole set of actors. */
export const PATCH = protectedRoute<Params>(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateCampaignSchema);
    return ok(await updateCampaign(auth, params.id, input, request));
  },
);

/** DELETE /api/campaigns/:id — needs threat_intel:write. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth, params }) => {
    await deleteCampaign(auth, params.id, request);
    return ok({ deleted: true });
  },
);
