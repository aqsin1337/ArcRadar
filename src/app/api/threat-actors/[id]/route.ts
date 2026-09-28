import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateActorSchema } from "@/lib/threat-intel/schema";
import { deleteActor, getActor, updateActor } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/threat-actors/:id — the actor with its malware, campaigns, techniques and indicators. */
export const GET = protectedRoute<Params>(
  { permissions: ["threat_intel:read"] },
  async ({ auth, params }) => ok(await getActor(auth.supabase, params.id)),
);

/**
 * PATCH /api/threat-actors/:id — needs threat_intel:write. Send only the fields to change. A link list
 * (`malware_ids`, `campaign_ids`, `technique_ids`) replaces that whole set; leave it out to keep it.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateActorSchema);
    return ok(await updateActor(auth, params.id, input, request));
  },
);

/** DELETE /api/threat-actors/:id — needs threat_intel:write. */
export const DELETE = protectedRoute<Params>(
  { permissions: ["threat_intel:write"] },
  async ({ request, auth, params }) => {
    await deleteActor(auth, params.id, request);
    return ok({ deleted: true });
  },
);
