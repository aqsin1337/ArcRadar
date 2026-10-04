import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getVulnerability } from "@/lib/vulnerabilities/service";

export const dynamic = "force-dynamic";

type Params = { cve: string };

/** GET /api/vulnerabilities/:cve — one CVE with its affected products and tracking indicator. Needs vulnerabilities:read. */
export const GET = protectedRoute<Params>(
  { permissions: ["vulnerabilities:read"] },
  async ({ auth, params }) => ok(await getVulnerability(auth.supabase, params.cve)),
);
