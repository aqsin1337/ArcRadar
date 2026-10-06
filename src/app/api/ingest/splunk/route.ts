import { after } from "next/server";
import { ingestRoute } from "@/lib/api/ingest-route";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { writeAuditLog } from "@/lib/audit/write";
import { MAX_BODY_BYTES } from "@/lib/telemetry/constants";
import { enrichIngestedIndicators } from "@/lib/telemetry/enrich";
import { ingestRecords } from "@/lib/telemetry/repository";
import { ingestBatch } from "@/lib/telemetry/service";
import { splunkBatchSchema, splunkSource } from "@/lib/telemetry/splunk";

export const dynamic = "force-dynamic";

/**
 * POST /api/ingest/splunk  { alerts: [ { sid, search_name, result, configuration?, ... }, ... ] }
 * (1 to 100 alerts, up to 1 MiB). Authenticated by an API key with the `ingest:splunk` scope
 * (`Authorization: Bearer arc_...`), not by a session. Each item is one result of an ArcRadar-written
 * saved search that triggered; it becomes an event and an alert (severity and MITRE ids come from the
 * saved search's parameters), public IPs, hashes and URLs in the result become indicators (verdict
 * unknown), and the host becomes an asset. Idempotent per (search name, search id, result): a retry
 * changes nothing. An item that cannot be used is listed in `rejected`; it never fails the request.
 * Answers like `/api/ingest/wazuh`. Rate-limited per key (`ingestByKey`).
 */
export const POST = ingestRoute(
  { scope: "ingest:splunk", rateLimit: "ingestByKey" },
  async ({ request, principal }) => {
    const body = await parseJsonBody(request, splunkBatchSchema, MAX_BODY_BYTES);
    return ok(
      await ingestBatch(principal, splunkSource, body.alerts, request, {
        store: ingestRecords,
        audit: writeAuditLog,
        enrich: (records) => after(() => enrichIngestedIndicators(records, request)),
      }),
    );
  },
);
