import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { vulnerabilityListQuerySchema } from "@/lib/vulnerabilities/schema";
import { listVulnerabilities } from "@/lib/vulnerabilities/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/vulnerabilities?q&severity&exploit_status&origin&min_cvss&sort&order&page&page_size
 * Text search (all terms must match the CVE id, title, description, or an affected vendor or
 * product), filters, sorting and pagination. Needs vulnerabilities:read.
 */
export const GET = protectedRoute(
  { permissions: ["vulnerabilities:read"] },
  async ({ request, auth }) => {
    const query = parseQuery(request, vulnerabilityListQuerySchema);
    return ok(await listVulnerabilities(auth.supabase, query));
  },
);
