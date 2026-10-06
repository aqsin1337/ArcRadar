import { ingestRoute } from "@/lib/api/ingest-route";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { backtestBatchSchema } from "@/lib/siem-rules/backtest";
import { ingestBacktests } from "@/lib/siem-rules/backtest-service";
import { MAX_BODY_BYTES } from "@/lib/telemetry/constants";

export const dynamic = "force-dynamic";

/**
 * POST /api/ingest/splunk/backtests  { results: [ { rule_key, window_hours (24 or 168), kind, matches,
 * scanned?, sample?, search_sha256, error? } ] }   (1 to 200 results, up to 1 MiB)
 * Authenticated by an API key with the `ingest:splunk` scope. The Splunk host ran each ArcRadar rule's search
 * over the last 24 hours and 7 days and reports how often it would have fired; `search_sha256` is the digest of
 * the search that was tested, so ArcRadar can tell a result for an older version of the rule. A later report
 * for the same rule and window replaces the earlier one. Answers `{ results }`.
 */
export const POST = ingestRoute(
  { scope: "ingest:splunk", rateLimit: "ingestByKey" },
  async ({ request, principal }) => {
    const body = await parseJsonBody(request, backtestBatchSchema, MAX_BODY_BYTES);
    return ok(await ingestBacktests(principal, "splunk", body, request));
  },
);
