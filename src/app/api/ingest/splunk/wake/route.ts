import { z } from "zod";
import { ingestRoute } from "@/lib/api/ingest-route";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { WAKE_MAX_WAIT_SECONDS, waitForPush } from "@/lib/siem-rules/wake";

export const dynamic = "force-dynamic";
// The request waits for up to WAKE_MAX_WAIT_SECONDS; the platform's default limit may be shorter.
export const maxDuration = 60;

const querySchema = z.object({
  since: z.string().max(64).optional(),
  wait: z.coerce.number().int().min(0).max(WAKE_MAX_WAIT_SECONDS).default(WAKE_MAX_WAIT_SECONDS),
});

/**
 * GET /api/ingest/splunk/wake[?since=<revision>&wait=<seconds, 0-25>] — authenticated by an API key with the
 * `ingest:splunk` scope. The Splunk host keeps this request open and is answered `{ revision, changed }` as soon
 * as a rule has been pushed since `since` (then it pulls the rules and tests them), or after `wait` seconds with
 * `changed: false`, and asks again. Without `since` it answers at once with the current revision. The revision is
 * only the time of the latest push; it carries no rule. Rate-limited per key like the other ingest endpoints.
 */
export const GET = ingestRoute(
  { scope: "ingest:splunk", rateLimit: "ingestByKey" },
  async ({ request }) => {
    const { since, wait } = parseQuery(request, querySchema);
    return ok(await waitForPush("splunk", since ?? null, wait, request.signal));
  },
);
