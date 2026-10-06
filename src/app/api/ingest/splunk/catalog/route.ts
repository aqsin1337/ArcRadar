import { ingestRoute } from "@/lib/api/ingest-route";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { catalogBatchSchema } from "@/lib/siem-rules/catalog";
import { ingestCatalog } from "@/lib/siem-rules/catalog-service";
import { MAX_BODY_BYTES } from "@/lib/telemetry/constants";

export const dynamic = "force-dynamic";

/**
 * POST /api/ingest/splunk/catalog  { sources: [ { index, sourcetype, window_hours, events_sampled,
 * fields: [ { name, count, distinct?, values? } ] } ] }   (1 to 50 sources, up to 1 MiB)
 * Authenticated by an API key with the `ingest:splunk` scope. The Splunk host reports which fields its
 * data really has (how often, a few example values); each source's earlier report is replaced. The rule
 * form offers these names and the AI is told them. Answers `{ sources, fields }`. A field whose name
 * the database refuses is skipped, not fatal. Rate-limited per key like the alert endpoint.
 */
export const POST = ingestRoute(
  { scope: "ingest:splunk", rateLimit: "ingestByKey" },
  async ({ request, principal }) => {
    const body = await parseJsonBody(request, catalogBatchSchema, MAX_BODY_BYTES);
    return ok(await ingestCatalog(principal, "splunk", body, request));
  },
);
