import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { getFieldCatalog } from "@/lib/siem-rules/catalog-service";
import { requireSiem } from "@/lib/siem-rules/params";

export const dynamic = "force-dynamic";

type Params = { siem: string };

/**
 * GET /api/siem-rules/:siem/fields[?index=&sourcetype=] — the fields the SIEM host reported (per index and
 * sourcetype: how often each appears, a few example values), most common first. Needs rules:manage.
 * Empty `sources` until the host has reported.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["rules:manage"] },
  async ({ request, auth, params }) => {
    const url = new URL(request.url);
    return ok(
      await getFieldCatalog(auth.supabase, requireSiem(params.siem), {
        index: url.searchParams.get("index") ?? undefined,
        sourcetype: url.searchParams.get("sourcetype") ?? undefined,
      }),
    );
  },
);
