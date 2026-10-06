import "server-only";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient } from "@/lib/auth/context";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import type { CatalogBatch, FieldCatalog } from "./catalog";
import { findCatalog, storeCatalog } from "./catalog-repository";
import type { SiemId } from "./constants";

type RequestLike = { headers: Headers };

export type CatalogDeps = {
  store: typeof storeCatalog;
  audit: typeof writeAuditLog;
};

const defaultDeps = (): CatalogDeps => ({ store: storeCatalog, audit: writeAuditLog });

/**
 * Records what a SIEM host reported about its fields and audits it once: who sent it and how much,
 * never the example values themselves (they come from real logs). The API key was verified by the route.
 */
export async function ingestCatalog(
  principal: ApiKeyPrincipal,
  siem: SiemId,
  body: CatalogBatch,
  request: RequestLike,
  deps: CatalogDeps = defaultDeps(),
): Promise<{ sources: number; fields: number }> {
  const result = await deps.store(siem, body.sources);
  await deps.audit(
    {
      action: "ingest.catalog",
      userId: null,
      entityType: "api_key",
      entityId: principal.keyId,
      metadata: {
        siem,
        key_name: principal.keyName,
        key_prefix: principal.keyPrefix,
        owner_id: principal.ownerId,
        sources: result.sources,
        fields: result.fields,
      },
    },
    request,
  );
  return result;
}

export const getFieldCatalog = (
  supabase: AuthClient,
  siem: SiemId,
  options: { index?: string; sourcetype?: string } = {},
): Promise<FieldCatalog> => findCatalog(supabase, siem, options);
