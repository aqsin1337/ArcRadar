import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { techniqueListQuerySchema } from "@/lib/threat-intel/schema";
import { listTechniques } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/mitre?q&tactic&sort&order&page&page_size
 * The MITRE ATT&CK techniques the workspace knows (reference data, read-only here). Text search over
 * the id, name, description and tactics; `tactic` filters by an exact tactic name. Needs threat_intel:read.
 */
export const GET = protectedRoute(
  { permissions: ["threat_intel:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, techniqueListQuerySchema);
    return ok(await listTechniques(auth.supabase, query));
  },
);
