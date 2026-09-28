import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getTechnique } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/** GET /api/mitre/:id — one technique (T1566, T1078.001) with the threat actors known to use it. */
export const GET = protectedRoute<Params>(
  { permissions: ["threat_intel:read"] },
  async ({ auth, params }) => ok(await getTechnique(auth.supabase, params.id)),
);
