import "server-only";
import type { PostgrestError } from "@supabase/supabase-js";
import { ApiError, apiErrors } from "@/lib/api/errors";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import type { Indicator, IndicatorType, RelationshipType } from "@/types/domain";
import type { CreateIndicatorInput, IndicatorListQuery, UpdateIndicatorInput } from "./schema";
import type { IndicatorDetail, IndicatorRelationship, IndicatorTag, LinkedEntity } from "./types";
import { VALUE_HINTS, normalizeIndicatorValue } from "./value";

/*
 * All queries use the caller's own client, so row level security is the final authority on what is
 * visible and writable, whatever the route guard decided.
 */

function validationIssue(path: string, message: string) {
  return apiErrors.validation({ issues: [{ path, message }] });
}

/** Turns constraint violations from a write into messages that name the field. */
function toWriteError(error: PostgrestError, type?: IndicatorType): ApiError {
  const text = error.message ?? "";
  if (error.code === "23514" && text.includes("indicators_seen_order")) {
    return validationIssue("last_seen", "Last seen cannot be earlier than first seen.");
  }
  if (error.code === "23514" && text.includes("indicators_value_valid")) {
    return validationIssue(
      "value",
      type ? VALUE_HINTS[type].error : "This value is not valid for the chosen type.",
    );
  }
  return toApiError(error);
}

/** One page of indicators matching the text search and filters, plus the total match count. */
export async function findIndicators(
  supabase: AuthClient,
  query: IndicatorListQuery,
): Promise<{ rows: Indicator[]; total: number }> {
  const { from, to } = toRange(query);

  // search_indicators() answers the text and tag question; everything else is ordinary PostgREST.
  const build = () => {
    let request = supabase.rpc(
      "search_indicators",
      { p_query: query.q, p_tag: query.tag },
      { count: "exact" },
    );
    if (query.type) request = request.eq("type", query.type);
    if (query.status) request = request.eq("status", query.status);
    if (query.verdict) request = request.eq("verdict", query.verdict);
    if (query.severity) request = request.eq("severity", query.severity);
    if (query.origin) request = request.eq("origin", query.origin);
    return request;
  };

  const sortColumn = query.sort === "value" ? "value_normalized" : query.sort;
  const { data, error, count } = await build()
    .order(sortColumn, { ascending: query.order === "asc" })
    .order("id", { ascending: true }) // a stable tie-breaker keeps pages from overlapping
    .range(from, to);

  if (error?.code === "PGRST103") {
    // The requested page is past the last row (a stale link, a hand-typed page number). PostgREST
    // refuses such a range, so ask for the first row only, to learn the total, and return no rows.
    const first = await build().range(0, 0);
    if (first.error) throw toApiError(first.error);
    return { rows: [], total: first.count ?? 0 };
  }
  if (error) throw toApiError(error);

  return { rows: data ?? [], total: count ?? 0 };
}

/** Tags for a set of indicators, keyed by indicator id. */
export async function findTagsByIndicator(
  supabase: AuthClient,
  indicatorIds: string[],
): Promise<Map<string, IndicatorTag[]>> {
  const byIndicator = new Map<string, IndicatorTag[]>();
  if (indicatorIds.length === 0) return byIndicator;

  const { data, error } = await supabase
    .from("indicator_tags")
    .select("indicator_id, tags(id, name, color)")
    .in("indicator_id", indicatorIds);
  if (error) throw toApiError(error);

  for (const row of data) {
    if (!row.tags) continue;
    byIndicator.set(row.indicator_id, [...(byIndicator.get(row.indicator_id) ?? []), row.tags]);
  }
  for (const tags of byIndicator.values()) tags.sort((a, b) => a.name.localeCompare(b.name));
  return byIndicator;
}

/** Every tag, for filter menus and tag suggestions. */
export async function findAllTags(supabase: AuthClient): Promise<IndicatorTag[]> {
  const { data, error } = await supabase
    .from("tags")
    .select("id, name, color")
    .order("name")
    .limit(500);
  if (error) throw toApiError(error);
  return data;
}

type LinkRow<K extends string> = { [P in K]: LinkedEntity | null };
const linked = <K extends string>(rows: LinkRow<K>[], key: K): LinkedEntity[] =>
  rows.flatMap((row) => (row[key] ? [row[key]] : [])).sort((a, b) => a.name.localeCompare(b.name));

/** One indicator with its tags, linked actors / campaigns / malware and relationships. */
export async function findIndicatorDetail(
  supabase: AuthClient,
  id: string,
): Promise<IndicatorDetail | null> {
  const [indicator, relationships] = await Promise.all([
    supabase
      .from("indicators")
      .select(
        "*, indicator_tags(tags(id, name, color)), indicator_threat_actors(threat_actors(id, name, origin)), indicator_campaigns(campaigns(id, name, origin)), indicator_malware(malware(id, name, origin))",
      )
      .eq("id", id)
      .maybeSingle(),
    supabase
      .from("indicator_relationships")
      .select(
        "id, relationship, source_indicator_id, target_indicator_id, source:indicators!source_indicator_id(id, type, value), target:indicators!target_indicator_id(id, type, value)",
      )
      .or(`source_indicator_id.eq.${id},target_indicator_id.eq.${id}`)
      .order("created_at"),
  ]);
  if (indicator.error) throw toApiError(indicator.error);
  if (relationships.error) throw toApiError(relationships.error);
  if (!indicator.data) return null;

  let createdByName: string | null = null;
  if (indicator.data.created_by) {
    const author = await supabase
      .from("profiles")
      .select("display_name")
      .eq("id", indicator.data.created_by)
      .maybeSingle();
    createdByName = author.data?.display_name ?? null;
  }

  const {
    indicator_tags,
    indicator_threat_actors,
    indicator_campaigns,
    indicator_malware,
    ...row
  } = indicator.data;

  const related: IndicatorRelationship[] = relationships.data.flatMap((link) => {
    const outgoing = link.source_indicator_id === id;
    const other = outgoing ? link.target : link.source;
    return other
      ? [
          {
            id: link.id,
            relationship: link.relationship,
            direction: outgoing ? "outgoing" : "incoming",
            other,
          } as const,
        ]
      : [];
  });

  return {
    ...row,
    created_by_name: createdByName,
    tags: indicator_tags
      .flatMap((link) => (link.tags ? [link.tags] : []))
      .sort((a, b) => a.name.localeCompare(b.name)),
    threat_actors: linked(indicator_threat_actors, "threat_actors"),
    campaigns: linked(indicator_campaigns, "campaigns"),
    malware: linked(indicator_malware, "malware"),
    relationships: related,
  };
}

/** The indicator with this type and (normalized) value, if the caller can see one. */
export async function findIndicatorByKey(
  supabase: AuthClient,
  type: IndicatorType,
  value: string,
): Promise<Indicator | null> {
  const { data, error } = await supabase
    .from("indicators")
    .select("*")
    .eq("type", type)
    .eq("value_normalized", normalizeIndicatorValue(type, value))
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Inserts one indicator (tags are set separately). `origin` and `created_by` come from the database. */
export async function insertIndicator(
  supabase: AuthClient,
  input: Omit<CreateIndicatorInput, "tags">,
): Promise<Indicator> {
  const { data, error } = await supabase.from("indicators").insert(input).select("*").single();
  if (error) {
    if (error.code === "23505") {
      const existing = await findIndicatorByKey(supabase, input.type, input.value).catch(
        () => null,
      );
      throw apiErrors.conflict(
        "This indicator already exists.",
        existing ? { existing_id: existing.id } : undefined,
      );
    }
    throw toWriteError(error, input.type);
  }
  return data;
}

export async function updateIndicatorRow(
  supabase: AuthClient,
  id: string,
  patch: Omit<UpdateIndicatorInput, "tags">,
): Promise<Indicator | null> {
  // With nothing to change but tags, just read the row (an empty UPDATE is a no-op for PostgREST).
  if (Object.keys(patch).length === 0) {
    const { data, error } = await supabase
      .from("indicators")
      .select("*")
      .eq("id", id)
      .maybeSingle();
    if (error) throw toApiError(error);
    return data;
  }

  const { data, error } = await supabase
    .from("indicators")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw toWriteError(error);
  return data;
}

export async function deleteIndicatorRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Indicator, "id" | "type" | "value" | "origin"> | null> {
  const { data, error } = await supabase
    .from("indicators")
    .delete()
    .eq("id", id)
    .select("id, type, value, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Just the columns that identify an indicator, for existence checks and audit entries. */
export async function findIndicatorIdentity(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Indicator, "id" | "type" | "value"> | null> {
  const { data, error } = await supabase
    .from("indicators")
    .select("id, type, value")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/**
 * Sets which threat actors, campaigns and malware families an indicator is linked to, atomically,
 * through set_indicator_links(). A list left out is kept as it is; an empty one clears that kind.
 */
export async function replaceIndicatorLinks(
  supabase: AuthClient,
  id: string,
  links: { actors?: string[]; campaigns?: string[]; malware?: string[] },
): Promise<void> {
  const { error } = await supabase.rpc("set_indicator_links", {
    p_indicator_id: id,
    p_actors: links.actors,
    p_campaigns: links.campaigns,
    p_malware: links.malware,
  });
  if (error) {
    if (error.code === "23503") {
      throw validationIssue("links", "One of the linked records does not exist.");
    }
    throw toApiError(error);
  }
}

/** Relates two indicators: `sourceId` <relationship> `targetId`. */
export async function insertRelationship(
  supabase: AuthClient,
  sourceId: string,
  targetId: string,
  relationship: RelationshipType,
): Promise<{ id: string }> {
  const { data, error } = await supabase
    .from("indicator_relationships")
    .insert({
      source_indicator_id: sourceId,
      target_indicator_id: targetId,
      relationship,
    })
    .select("id")
    .single();
  if (error) {
    if (error.code === "23505")
      throw apiErrors.conflict("These indicators are already related this way.");
    if (error.code === "23503")
      throw validationIssue("target_id", "That indicator does not exist.");
    if (error.code === "23514") {
      throw validationIssue("target_id", "An indicator cannot be related to itself.");
    }
    throw toApiError(error);
  }
  return data;
}

/** Removes a relationship, but only one that involves `indicatorId` (as source or target). */
export async function deleteRelationshipRow(
  supabase: AuthClient,
  indicatorId: string,
  relationshipId: string,
): Promise<{
  id: string;
  relationship: RelationshipType;
  source_indicator_id: string;
  target_indicator_id: string;
} | null> {
  const { data, error } = await supabase
    .from("indicator_relationships")
    .delete()
    .eq("id", relationshipId)
    .or(`source_indicator_id.eq.${indicatorId},target_indicator_id.eq.${indicatorId}`)
    .select("id, relationship, source_indicator_id, target_indicator_id")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Replaces the tag set atomically (creating unknown tags) through set_indicator_tags(). */
export async function replaceIndicatorTags(
  supabase: AuthClient,
  id: string,
  tags: string[],
): Promise<void> {
  const { error } = await supabase.rpc("set_indicator_tags", {
    p_indicator_id: id,
    p_tags: tags,
  });
  if (error) {
    if (error.code === "23514") {
      throw validationIssue("tags", "Check the tags: at most 20, up to 50 characters each.");
    }
    throw toApiError(error);
  }
}
