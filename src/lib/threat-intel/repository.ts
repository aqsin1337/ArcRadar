import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { fetchPage } from "@/lib/api/fetch-page";
import { toRange } from "@/lib/api/pagination";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { findDisplayNames } from "@/lib/team/repository";
import type { Campaign, Malware, MitreTechnique, ThreatActor } from "@/types/domain";
import { LINKED_INDICATOR_LIMIT } from "./constants";
import type {
  ActorListQuery,
  CampaignListQuery,
  CreateActorInput,
  CreateCampaignInput,
  CreateMalwareInput,
  MalwareListQuery,
  TechniqueListQuery,
  UpdateActorInput,
  UpdateCampaignInput,
  UpdateMalwareInput,
} from "./schema";
import type {
  ActorDetail,
  ActorListItem,
  ActorRef,
  CampaignDetail,
  CampaignListItem,
  LinkOptions,
  LinkedIndicator,
  LinkedIndicators,
  MalwareDetail,
  MalwareListItem,
  TechniqueDetail,
} from "./types";

/*
 * All queries use the caller's own client, so row level security is the final authority on what is
 * visible and writable, whatever the route guard decided. Links between records are written through
 * the set_*_links() SQL functions, which replace a whole set atomically.
 */

const countOf = (embedded: { count: number }[]) => embedded[0]?.count ?? 0;

const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);

const INDICATOR_COLUMNS = "id, type, value, verdict, severity, origin";

/** The indicator columns only: the inner-joined link rows the query needed for filtering stay behind. */
const toLinkedIndicator = (row: LinkedIndicator): LinkedIndicator => ({
  id: row.id,
  type: row.type,
  value: row.value,
  verdict: row.verdict,
  severity: row.severity,
  origin: row.origin,
});

// --- Threat actors --------------------------------------------------------------------------------

const ACTOR_LIST_SELECT = `*,
  malware:threat_actor_malware(count),
  campaigns:threat_actor_campaigns(count),
  techniques:threat_actor_techniques(count),
  indicators:indicator_threat_actors(count)`;

export async function findActors(
  supabase: AuthClient,
  query: ActorListQuery,
): Promise<{ rows: ActorListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase
      .rpc("search_threat_actors", { p_query: query.q }, { count: "exact" })
      .select(ACTOR_LIST_SELECT);
    if (query.origin) request = request.eq("origin", query.origin);
    return request;
  };

  const { rows, total } = await fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc", nullsFirst: false })
        .order("id", { ascending: true }) // a stable tie-breaker keeps pages from overlapping
        .range(from, to),
    () => build().range(0, 0),
  );
  return {
    rows: rows.map(({ malware, campaigns, techniques, indicators, ...row }) => ({
      ...row,
      counts: {
        malware: countOf(malware),
        campaigns: countOf(campaigns),
        techniques: countOf(techniques),
        indicators: countOf(indicators),
      },
    })),
    total,
  };
}

export async function findActorDetail(
  supabase: AuthClient,
  id: string,
): Promise<ActorDetail | null> {
  const { data, error } = await supabase
    .from("threat_actors")
    .select(
      `*,
      threat_actor_malware(malware(id, name, malware_type, origin)),
      threat_actor_campaigns(campaigns(id, name, status, origin, last_seen)),
      threat_actor_techniques(mitre_techniques(id, name, tactics))`,
    )
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const { threat_actor_malware, threat_actor_campaigns, threat_actor_techniques, ...row } = data;
  const [names, indicators] = await Promise.all([
    findDisplayNames(supabase, [row.created_by]),
    findActorIndicators(supabase, id),
  ]);
  return {
    ...row,
    created_by_name: row.created_by ? (names.get(row.created_by) ?? null) : null,
    malware: threat_actor_malware
      .flatMap((link) => (link.malware ? [link.malware] : []))
      .sort(byName),
    campaigns: threat_actor_campaigns
      .flatMap((link) => (link.campaigns ? [link.campaigns] : []))
      .sort(byName),
    techniques: threat_actor_techniques
      .flatMap((link) => (link.mitre_techniques ? [link.mitre_techniques] : []))
      .sort((a, b) => a.id.localeCompare(b.id)),
    indicators,
  };
}

async function findActorIndicators(supabase: AuthClient, id: string): Promise<LinkedIndicators> {
  const { data, error, count } = await supabase
    .from("indicators")
    .select(`${INDICATOR_COLUMNS}, indicator_threat_actors!inner(threat_actor_id)`, {
      count: "exact",
    })
    .eq("indicator_threat_actors.threat_actor_id", id)
    .order("value")
    .limit(LINKED_INDICATOR_LIMIT);
  if (error) throw toApiError(error);
  return {
    items: data.map(toLinkedIndicator),
    total: count ?? 0,
  };
}

export async function findActorRow(supabase: AuthClient, id: string): Promise<ThreatActor | null> {
  const { data, error } = await supabase
    .from("threat_actors")
    .select("*")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

type ActorColumns = Omit<CreateActorInput, "malware_ids" | "campaign_ids" | "technique_ids">;

export async function insertActor(supabase: AuthClient, input: ActorColumns): Promise<ThreatActor> {
  const { data, error } = await supabase.from("threat_actors").insert(input).select("*").single();
  if (error) throw writeError(error, "threat actor");
  return data;
}

export async function updateActorRow(
  supabase: AuthClient,
  id: string,
  patch: Omit<UpdateActorInput, "malware_ids" | "campaign_ids" | "technique_ids">,
): Promise<ThreatActor | null> {
  const { data, error } = await supabase
    .from("threat_actors")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw writeError(error, "threat actor");
  return data;
}

export async function deleteActorRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<ThreatActor, "id" | "name" | "origin"> | null> {
  const { data, error } = await supabase
    .from("threat_actors")
    .delete()
    .eq("id", id)
    .select("id, name, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function setActorLinks(
  supabase: AuthClient,
  id: string,
  links: { malware?: string[]; campaigns?: string[]; techniques?: string[] },
): Promise<void> {
  if (!links.malware && !links.campaigns && !links.techniques) return;
  const { error } = await supabase.rpc("set_threat_actor_links", {
    p_actor_id: id,
    p_malware: links.malware,
    p_campaigns: links.campaigns,
    p_techniques: links.techniques,
  });
  if (error) throw linkError(error);
}

// --- Campaigns ------------------------------------------------------------------------------------

const CAMPAIGN_LIST_SELECT = `*,
  actors:threat_actor_campaigns(count),
  indicators:indicator_campaigns(count)`;

export async function findCampaigns(
  supabase: AuthClient,
  query: CampaignListQuery,
): Promise<{ rows: CampaignListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase
      .rpc("search_campaigns", { p_query: query.q }, { count: "exact" })
      .select(CAMPAIGN_LIST_SELECT);
    if (query.status) request = request.eq("status", query.status);
    if (query.origin) request = request.eq("origin", query.origin);
    return request;
  };

  const { rows, total } = await fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc", nullsFirst: false })
        .order("id", { ascending: true })
        .range(from, to),
    () => build().range(0, 0),
  );
  return {
    rows: rows.map(({ actors, indicators, ...row }) => ({
      ...row,
      counts: { actors: countOf(actors), indicators: countOf(indicators) },
    })),
    total,
  };
}

export async function findCampaignDetail(
  supabase: AuthClient,
  id: string,
): Promise<CampaignDetail | null> {
  const { data, error } = await supabase
    .from("campaigns")
    .select("*, threat_actor_campaigns(threat_actors(id, name, origin))")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const { threat_actor_campaigns, ...row } = data;
  const [names, indicators] = await Promise.all([
    findDisplayNames(supabase, [row.created_by]),
    findCampaignIndicators(supabase, id),
  ]);
  return {
    ...row,
    created_by_name: row.created_by ? (names.get(row.created_by) ?? null) : null,
    actors: threat_actor_campaigns
      .flatMap((link) => (link.threat_actors ? [link.threat_actors] : []))
      .sort(byName),
    indicators,
  };
}

async function findCampaignIndicators(supabase: AuthClient, id: string): Promise<LinkedIndicators> {
  const { data, error, count } = await supabase
    .from("indicators")
    .select(`${INDICATOR_COLUMNS}, indicator_campaigns!inner(campaign_id)`, { count: "exact" })
    .eq("indicator_campaigns.campaign_id", id)
    .order("value")
    .limit(LINKED_INDICATOR_LIMIT);
  if (error) throw toApiError(error);
  return {
    items: data.map(toLinkedIndicator),
    total: count ?? 0,
  };
}

export async function findCampaignRow(supabase: AuthClient, id: string): Promise<Campaign | null> {
  const { data, error } = await supabase.from("campaigns").select("*").eq("id", id).maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function insertCampaign(
  supabase: AuthClient,
  input: Omit<CreateCampaignInput, "actor_ids">,
): Promise<Campaign> {
  const { data, error } = await supabase.from("campaigns").insert(input).select("*").single();
  if (error) throw writeError(error, "campaign");
  return data;
}

export async function updateCampaignRow(
  supabase: AuthClient,
  id: string,
  patch: Omit<UpdateCampaignInput, "actor_ids">,
): Promise<Campaign | null> {
  const { data, error } = await supabase
    .from("campaigns")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw writeError(error, "campaign");
  return data;
}

export async function deleteCampaignRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Campaign, "id" | "name" | "origin"> | null> {
  const { data, error } = await supabase
    .from("campaigns")
    .delete()
    .eq("id", id)
    .select("id, name, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function setCampaignActors(
  supabase: AuthClient,
  id: string,
  actors: string[],
): Promise<void> {
  const { error } = await supabase.rpc("set_campaign_actors", {
    p_campaign_id: id,
    p_actors: actors,
  });
  if (error) throw linkError(error);
}

// --- Malware --------------------------------------------------------------------------------------

const MALWARE_LIST_SELECT = `*,
  actors:threat_actor_malware(count),
  indicators:indicator_malware(count)`;

export async function findMalwareFamilies(
  supabase: AuthClient,
  query: MalwareListQuery,
): Promise<{ rows: MalwareListItem[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase
      .rpc("search_malware", { p_query: query.q }, { count: "exact" })
      .select(MALWARE_LIST_SELECT);
    if (query.type) request = request.eq("malware_type", query.type);
    if (query.origin) request = request.eq("origin", query.origin);
    return request;
  };

  const { rows, total } = await fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc", nullsFirst: false })
        .order("id", { ascending: true })
        .range(from, to),
    () => build().range(0, 0),
  );
  return {
    rows: rows.map(({ actors, indicators, ...row }) => ({
      ...row,
      counts: { actors: countOf(actors), indicators: countOf(indicators) },
    })),
    total,
  };
}

export async function findMalwareDetail(
  supabase: AuthClient,
  id: string,
): Promise<MalwareDetail | null> {
  const { data, error } = await supabase
    .from("malware")
    .select("*, threat_actor_malware(threat_actors(id, name, origin))")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const { threat_actor_malware, ...row } = data;
  const [names, indicators] = await Promise.all([
    findDisplayNames(supabase, [row.created_by]),
    findMalwareIndicators(supabase, id),
  ]);
  return {
    ...row,
    created_by_name: row.created_by ? (names.get(row.created_by) ?? null) : null,
    actors: threat_actor_malware
      .flatMap((link) => (link.threat_actors ? [link.threat_actors] : []))
      .sort(byName),
    indicators,
  };
}

async function findMalwareIndicators(supabase: AuthClient, id: string): Promise<LinkedIndicators> {
  const { data, error, count } = await supabase
    .from("indicators")
    .select(`${INDICATOR_COLUMNS}, indicator_malware!inner(malware_id)`, { count: "exact" })
    .eq("indicator_malware.malware_id", id)
    .order("value")
    .limit(LINKED_INDICATOR_LIMIT);
  if (error) throw toApiError(error);
  return {
    items: data.map(toLinkedIndicator),
    total: count ?? 0,
  };
}

export async function findMalwareRow(supabase: AuthClient, id: string): Promise<Malware | null> {
  const { data, error } = await supabase.from("malware").select("*").eq("id", id).maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function insertMalware(
  supabase: AuthClient,
  input: Omit<CreateMalwareInput, "actor_ids">,
): Promise<Malware> {
  const { data, error } = await supabase.from("malware").insert(input).select("*").single();
  if (error) throw writeError(error, "malware family");
  return data;
}

export async function updateMalwareRow(
  supabase: AuthClient,
  id: string,
  patch: Omit<UpdateMalwareInput, "actor_ids">,
): Promise<Malware | null> {
  const { data, error } = await supabase
    .from("malware")
    .update(patch)
    .eq("id", id)
    .select("*")
    .maybeSingle();
  if (error) throw writeError(error, "malware family");
  return data;
}

export async function deleteMalwareRow(
  supabase: AuthClient,
  id: string,
): Promise<Pick<Malware, "id" | "name" | "origin"> | null> {
  const { data, error } = await supabase
    .from("malware")
    .delete()
    .eq("id", id)
    .select("id, name, origin")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export async function setMalwareActors(
  supabase: AuthClient,
  id: string,
  actors: string[],
): Promise<void> {
  const { error } = await supabase.rpc("set_malware_actors", {
    p_malware_id: id,
    p_actors: actors,
  });
  if (error) throw linkError(error);
}

/** The distinct malware types in use, for a filter menu. */
export async function findMalwareTypes(supabase: AuthClient): Promise<string[]> {
  const { data, error } = await supabase.from("malware").select("malware_type");
  if (error) throw toApiError(error);
  return [...new Set(data.flatMap((row) => (row.malware_type ? [row.malware_type] : [])))].sort(
    (a, b) => a.localeCompare(b),
  );
}

// --- MITRE ATT&CK techniques (reference data) -------------------------------------------------------

export async function findTechniques(
  supabase: AuthClient,
  query: TechniqueListQuery,
): Promise<{ rows: MitreTechnique[]; total: number }> {
  const { from, to } = toRange(query);
  const build = () => {
    let request = supabase.rpc("search_mitre_techniques", { p_query: query.q }, { count: "exact" });
    if (query.tactic) request = request.contains("tactics", [query.tactic]);
    return request;
  };

  return fetchPage(
    () =>
      build()
        .order(query.sort, { ascending: query.order === "asc" })
        .order("id", { ascending: true })
        .range(from, to),
    () => build().range(0, 0),
  );
}

export async function findTechniqueDetail(
  supabase: AuthClient,
  id: string,
): Promise<TechniqueDetail | null> {
  const { data, error } = await supabase
    .from("mitre_techniques")
    .select("*, threat_actor_techniques(threat_actors(id, name, origin))")
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  if (!data) return null;

  const { threat_actor_techniques, ...row } = data;
  return {
    ...row,
    actors: threat_actor_techniques
      .flatMap((link) => (link.threat_actors ? [link.threat_actors] : []))
      .sort(byName),
  };
}

/** The distinct tactics across all techniques, for a filter menu. */
export async function findTactics(supabase: AuthClient): Promise<string[]> {
  const { data, error } = await supabase.from("mitre_techniques").select("tactics");
  if (error) throw toApiError(error);
  return [...new Set(data.flatMap((row) => row.tactics))].sort((a, b) => a.localeCompare(b));
}

// --- Choices for forms and link checks -------------------------------------------------------------

const OPTION_LIMIT = 500;

/** Everything a create or edit form can link to. */
export async function findLinkOptions(supabase: AuthClient): Promise<LinkOptions> {
  const [actors, malware, campaigns, techniques] = await Promise.all([
    supabase.from("threat_actors").select("id, name, origin").order("name").limit(OPTION_LIMIT),
    supabase.from("malware").select("id, name, malware_type").order("name").limit(OPTION_LIMIT),
    supabase.from("campaigns").select("id, name, status").order("name").limit(OPTION_LIMIT),
    supabase.from("mitre_techniques").select("id, name").order("id").limit(OPTION_LIMIT),
  ]);
  for (const result of [actors, malware, campaigns, techniques]) {
    if (result.error) throw toApiError(result.error);
  }
  return {
    actors: (actors.data ?? []) as ActorRef[],
    malware: malware.data ?? [],
    campaigns: campaigns.data ?? [],
    techniques: techniques.data ?? [],
  };
}

type LinkTable = "threat_actors" | "malware" | "campaigns" | "mitre_techniques";

/**
 * Throws a validation error naming `path` when any of `ids` is not a record the caller can see. This
 * runs before anything is written, so a bad link never leaves a half-saved record behind.
 */
export async function assertLinkTargetsExist(
  supabase: AuthClient,
  table: LinkTable,
  ids: string[],
  path: string,
): Promise<void> {
  if (ids.length === 0) return;
  const { data, error } = await supabase
    .from(table as "malware")
    .select("id")
    .in("id", ids);
  if (error) throw toApiError(error);
  if (new Set(data.map((row) => row.id)).size < new Set(ids).size) {
    throw apiErrors.validation({
      issues: [{ path, message: "One of the linked records does not exist." }],
    });
  }
}

// --- Errors ---------------------------------------------------------------------------------------

type DbError = { code?: string; message: string; details?: string | null };

/** A write that broke the unique name rule says so; everything else is mapped generically. */
function writeError(error: DbError, noun: string) {
  if (error.code === "23505") return apiErrors.conflict(`A ${noun} with this name already exists.`);
  return toApiError(error);
}

function linkError(error: DbError) {
  if (error.code === "23503") {
    return apiErrors.validation({
      issues: [{ path: "links", message: "One of the linked records does not exist." }],
    });
  }
  return toApiError(error);
}
