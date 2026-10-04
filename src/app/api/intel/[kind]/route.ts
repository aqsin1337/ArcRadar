import { apiErrors } from "@/lib/api/errors";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { findDisabledLookupProviders } from "@/lib/integrations/service";
import {
  defaultDeps,
  intelKindSchema,
  intelQuerySchema,
  lookupIntel,
  requireTarget,
} from "@/lib/intel/service";

export const dynamic = "force-dynamic";

type Params = { kind: string };

/**
 * GET /api/intel/:kind?value=<subject>   (kind: ip | domain | url | hash)
 * Looks a subject up: the answers of every provider that delivered (each labelled demo or
 * external, with when it was retrieved), what happened with each provider, and what the workspace
 * knows about the subject. Needs indicators:read. Live providers are only asked for analysts and
 * administrators, and never for private or reserved values, or a provider an administrator has
 * turned off on the Integrations page; the demo provider answers otherwise.
 */
export const GET = protectedRoute<Params>(
  { permissions: ["indicators:read"] },
  async ({ request, auth, params }) => {
    const kind = intelKindSchema.safeParse(params.kind);
    if (!kind.success) throw apiErrors.notFound("Unknown kind of lookup.");
    const { value } = parseQuery(request, intelQuerySchema);

    const disabled = await findDisabledLookupProviders(auth.supabase);
    const deps = defaultDeps();
    if (disabled.size > 0) {
      deps.registry = {
        ...deps.registry,
        external: deps.registry.external.filter((provider) => !disabled.has(provider.info.id)),
      };
    }
    return ok(await lookupIntel(auth, requireTarget(kind.data, value), request, deps));
  },
);
