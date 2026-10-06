import "server-only";
import { writeAuditLog } from "@/lib/audit/write";
import type { ApiKeyPrincipal } from "@/lib/api-keys/types";
import type { BacktestBatch } from "./backtest";
import { storeBacktests } from "./backtest-repository";
import type { SiemId } from "./constants";

type RequestLike = { headers: Headers };

export type BacktestDeps = {
  store: typeof storeBacktests;
  audit: typeof writeAuditLog;
};

const defaultDeps = (): BacktestDeps => ({ store: storeBacktests, audit: writeAuditLog });

/**
 * Records what a SIEM host found when it ran rules' searches over past data, and audits it once: who sent
 * it and how many results. The API key was verified by the route.
 */
export async function ingestBacktests(
  principal: ApiKeyPrincipal,
  siem: SiemId,
  body: BacktestBatch,
  request: RequestLike,
  deps: BacktestDeps = defaultDeps(),
): Promise<{ results: number }> {
  const result = await deps.store(siem, body.results);
  await deps.audit(
    {
      action: "ingest.backtest",
      userId: null,
      entityType: "api_key",
      entityId: principal.keyId,
      metadata: {
        siem,
        key_name: principal.keyName,
        key_prefix: principal.keyPrefix,
        owner_id: principal.ownerId,
        results: result.results,
      },
    },
    request,
  );
  return result;
}
