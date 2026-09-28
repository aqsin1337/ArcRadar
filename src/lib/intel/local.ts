import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import {
  findIndicatorByKey,
  findIndicatorDetail,
  findIndicators,
} from "@/lib/indicators/repository";
import { indicatorListQuerySchema } from "@/lib/indicators/schema";
import type { IndicatorDetail } from "@/lib/indicators/types";
import type { IntelTarget } from "./target";
import { buildTimeline, type LocalContext, type RelatedIndicator } from "./timeline";

const RELATED_LIMIT = 8;
const ACTIVITY_LIMIT = 10;
const MAX_SEARCH_LENGTH = 200;

/** The text that finds other indicators mentioning this subject, or null when it would be meaningless. */
function searchTextFor(target: IntelTarget): string | null {
  const text = target.kind === "url" ? target.host : target.kind === "hash" ? null : target.value;
  return text && text.length <= MAX_SEARCH_LENGTH ? text : null;
}

/**
 * What the workspace itself knows about a subject: the indicator that tracks it (if any) with its
 * relationships and links, other indicators that mention it, and the alerts, events and
 * investigations tied to that indicator. Everything is read with the caller's own client, so row
 * level security decides what they see.
 */
export async function loadLocalContext(
  supabase: AuthClient,
  target: IntelTarget,
): Promise<LocalContext> {
  const tracked = await findIndicatorByKey(supabase, target.indicatorType, target.value);
  const text = searchTextFor(target);

  const [indicator, matches, alerts, events, investigations] = await Promise.all([
    tracked
      ? findIndicatorDetail(supabase, tracked.id)
      : Promise.resolve<IndicatorDetail | null>(null),
    text
      ? findIndicators(
          supabase,
          indicatorListQuerySchema.parse({ q: text, page: 1, page_size: RELATED_LIMIT + 1 }),
        )
      : Promise.resolve(null),
    tracked
      ? supabase
          .from("alerts")
          .select("id, title, severity, status, created_at, origin")
          .eq("indicator_id", tracked.id)
          .order("created_at", { ascending: false })
          .limit(ACTIVITY_LIMIT)
      : Promise.resolve(null),
    tracked
      ? supabase
          .from("events")
          .select("id, title, severity, event_type, occurred_at, origin")
          .eq("indicator_id", tracked.id)
          .order("occurred_at", { ascending: false })
          .limit(ACTIVITY_LIMIT)
      : Promise.resolve(null),
    tracked
      ? supabase
          .from("investigation_indicators")
          .select("investigations(id, title, status, priority, created_at, origin)")
          .eq("indicator_id", tracked.id)
          .limit(ACTIVITY_LIMIT)
      : Promise.resolve(null),
  ]);

  for (const result of [alerts, events, investigations]) {
    if (result?.error) throw toApiError(result.error);
  }

  // Other indicators that mention the subject, without the tracked one and without those already
  // shown as relationships.
  const linked = new Set(indicator?.relationships.map((link) => link.other.id) ?? []);
  const related: RelatedIndicator[] = (matches?.rows ?? [])
    .filter((row) => row.id !== tracked?.id && !linked.has(row.id))
    .slice(0, RELATED_LIMIT)
    .map((row) => ({
      id: row.id,
      type: row.type,
      value: row.value,
      verdict: row.verdict,
      severity: row.severity,
      origin: row.origin,
    }));

  const context = {
    indicator,
    related,
    alerts: alerts?.data ?? [],
    events: events?.data ?? [],
    investigations: (investigations?.data ?? []).flatMap((row) =>
      row.investigations ? [row.investigations] : [],
    ),
  };
  return { ...context, timeline: buildTimeline(context) };
}
