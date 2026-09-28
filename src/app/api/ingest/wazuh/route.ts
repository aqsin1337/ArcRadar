import { ingestRoute } from "@/lib/api/ingest-route";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { MAX_BODY_BYTES } from "@/lib/telemetry/constants";
import { ingestBatch } from "@/lib/telemetry/service";
import { wazuhBatchSchema, wazuhSource } from "@/lib/telemetry/wazuh";

export const dynamic = "force-dynamic";

/**
 * POST /api/ingest/wazuh  { alerts: [ <Wazuh alert JSON>, ... ] }   (1 to 100 alerts, up to 1 MiB)
 * Authenticated by an API key with the `ingest:wazuh` scope (`Authorization: Bearer arc_...`), not by a
 * session. Every alert becomes an event; a rule level of 7 or more also becomes an alert; public IPs,
 * hashes and domains in it become indicators (verdict unknown); the agent becomes an asset. It is
 * idempotent: an alert already received (same manager and alert id) is counted as a duplicate and
 * changes nothing, so retries are safe. An alert that cannot be used is listed in `rejected` with a
 * reason; it never fails the request. Answers `{ received, events_created, alerts_created, duplicates,
 * assets_created, indicators_created, rejected }`. Rate-limited per key (`ingestByKey`): a real
 * sensor delivers steadily, so the cap only bites a misbehaving or compromised key.
 */
export const POST = ingestRoute(
  { scope: "ingest:wazuh", rateLimit: "ingestByKey" },
  async ({ request, principal }) => {
    const body = await parseJsonBody(request, wazuhBatchSchema, MAX_BODY_BYTES);
    return ok(await ingestBatch(principal, wazuhSource, body.alerts, request));
  },
);
