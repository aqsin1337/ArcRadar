import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getTechniqueDetail } from "@/lib/mitre/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/**
 * GET /api/mitre/:id — one technique (T1566, T1078.001): its description, tactics, sub-techniques,
 * what this workspace's alerts say about it and the newest of those alerts (a parent technique
 * includes the alerts that name one of its sub-techniques). Needs threat_intel:read; the alerts are
 * only the ones the caller may read.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["threat_intel:read"] },
  async ({ auth, params }) => ok(await getTechniqueDetail(auth.supabase, params.id)),
);
