import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { findDisabledLookupProviders } from "@/lib/integrations/service";
import { importVulnerabilitySchema } from "@/lib/vulnerabilities/schema";
import { defaultImportDeps, importVulnerability } from "@/lib/vulnerabilities/service";

export const dynamic = "force-dynamic";

/**
 * POST /api/vulnerabilities/import  { cve_id }
 * Fetches the CVE from the connected provider (NVD) and records it as external data, or refreshes
 * the external record already there. Needs vulnerabilities:write (administrators). 201 when the
 * record is new, 200 when refreshed; 503 when no provider is connected or an administrator has
 * turned it off; 404 when the provider has no such CVE; 409 when a demo or local record with that
 * id exists (it is never replaced).
 */
export const POST = protectedRoute(
  { permissions: ["vulnerabilities:write"] },
  async ({ request, auth }) => {
    const { cve_id } = await parseJsonBody(request, importVulnerabilitySchema);
    const disabled = await findDisabledLookupProviders(auth.supabase);
    const deps = await defaultImportDeps();
    if (disabled.has("nvd")) deps.provider = null;
    const { vulnerability, created } = await importVulnerability(auth, cve_id, request, deps);
    return ok(vulnerability, { status: created ? 201 : 200 });
  },
);
