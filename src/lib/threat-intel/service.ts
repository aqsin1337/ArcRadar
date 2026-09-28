import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuditAction } from "@/lib/audit/actions";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import type { MitreTechnique } from "@/types/domain";
import {
  assertLinkTargetsExist,
  deleteActorRow,
  deleteCampaignRow,
  deleteMalwareRow,
  findActorDetail,
  findActorRow,
  findActors,
  findCampaignDetail,
  findCampaignRow,
  findCampaigns,
  findLinkOptions,
  findMalwareDetail,
  findMalwareFamilies,
  findMalwareRow,
  findMalwareTypes,
  findTactics,
  findTechniqueDetail,
  findTechniques,
  insertActor,
  insertCampaign,
  insertMalware,
  setActorLinks,
  setCampaignActors,
  setMalwareActors,
  updateActorRow,
  updateCampaignRow,
  updateMalwareRow,
} from "./repository";
import {
  entityIdSchema,
  techniqueIdSchema,
  type ActorListQuery,
  type CampaignListQuery,
  type CreateActorInput,
  type CreateCampaignInput,
  type CreateMalwareInput,
  type MalwareListQuery,
  type TechniqueListQuery,
  type UpdateActorInput,
  type UpdateCampaignInput,
  type UpdateMalwareInput,
} from "./schema";
import type {
  ActorDetail,
  ActorListItem,
  CampaignDetail,
  CampaignListItem,
  LinkOptions,
  MalwareDetail,
  MalwareListItem,
  TechniqueDetail,
} from "./types";

type RequestLike = { headers: Headers };

/** Page-level check for ids taken from a URL: a malformed id is simply "not found". */
export const isEntityId = (id: string) => entityIdSchema.safeParse(id).success;

export const parseTechniqueId = (id: string): string | null => {
  const parsed = techniqueIdSchema.safeParse(id);
  return parsed.success ? parsed.data : null;
};

const audit = (
  auth: AuthContext,
  request: RequestLike,
  action: AuditAction,
  entityType: string,
  entityId: string,
  metadata: Record<string, string | number | boolean | string[] | null>,
) => writeAuditLog({ action, userId: auth.user.id, entityType, entityId, metadata }, request);

// --- Threat actors --------------------------------------------------------------------------------

export async function listActors(
  supabase: AuthClient,
  query: ActorListQuery,
): Promise<Page<ActorListItem>> {
  const { rows, total } = await findActors(supabase, query);
  return buildPage(rows, total, query);
}

export async function getActor(supabase: AuthClient, id: string): Promise<ActorDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Threat actor not found.");
  const detail = await findActorDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Threat actor not found.");
  return detail;
}

/** Creates a local threat actor (the database sets origin and owner) and its links. */
export async function createActor(
  auth: AuthContext,
  input: CreateActorInput,
  request: RequestLike,
): Promise<ActorDetail> {
  const { malware_ids, campaign_ids, technique_ids, ...columns } = input;
  const { supabase } = auth;
  await Promise.all([
    assertLinkTargetsExist(supabase, "malware", malware_ids ?? [], "malware_ids"),
    assertLinkTargetsExist(supabase, "campaigns", campaign_ids ?? [], "campaign_ids"),
    assertLinkTargetsExist(supabase, "mitre_techniques", technique_ids ?? [], "technique_ids"),
  ]);

  const row = await insertActor(supabase, columns);
  try {
    await setActorLinks(supabase, row.id, {
      malware: malware_ids,
      campaigns: campaign_ids,
      techniques: technique_ids,
    });
  } catch (error) {
    await deleteActorRow(supabase, row.id).catch(() => null); // do not leave a half-saved record
    throw error;
  }

  await audit(auth, request, "threat_actor.created", "threat_actor", row.id, {
    name: row.name,
    origin: row.origin,
    malware: malware_ids?.length ?? 0,
    campaigns: campaign_ids?.length ?? 0,
    techniques: technique_ids?.length ?? 0,
  });
  return getActor(supabase, row.id);
}

export async function updateActor(
  auth: AuthContext,
  id: string,
  input: UpdateActorInput,
  request: RequestLike,
): Promise<ActorDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Threat actor not found.");
  const { malware_ids, campaign_ids, technique_ids, ...columns } = input;
  const { supabase } = auth;

  const current = await findActorRow(supabase, id);
  if (!current) throw apiErrors.notFound("Threat actor not found.");
  await Promise.all([
    assertLinkTargetsExist(supabase, "malware", malware_ids ?? [], "malware_ids"),
    assertLinkTargetsExist(supabase, "campaigns", campaign_ids ?? [], "campaign_ids"),
    assertLinkTargetsExist(supabase, "mitre_techniques", technique_ids ?? [], "technique_ids"),
  ]);

  if (Object.keys(columns).length > 0) {
    const updated = await updateActorRow(supabase, id, columns);
    if (!updated) throw apiErrors.notFound("Threat actor not found.");
  }
  await setActorLinks(supabase, id, {
    malware: malware_ids,
    campaigns: campaign_ids,
    techniques: technique_ids,
  });

  await audit(auth, request, "threat_actor.updated", "threat_actor", id, {
    name: columns.name ?? current.name,
    fields: Object.keys(columns),
    links: [
      ...(malware_ids ? ["malware"] : []),
      ...(campaign_ids ? ["campaigns"] : []),
      ...(technique_ids ? ["techniques"] : []),
    ],
  });
  return getActor(supabase, id);
}

export async function deleteActor(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isEntityId(id)) throw apiErrors.notFound("Threat actor not found.");
  const removed = await deleteActorRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Threat actor not found.");
  await audit(auth, request, "threat_actor.deleted", "threat_actor", id, {
    name: removed.name,
    origin: removed.origin,
  });
}

// --- Campaigns ------------------------------------------------------------------------------------

export async function listCampaigns(
  supabase: AuthClient,
  query: CampaignListQuery,
): Promise<Page<CampaignListItem>> {
  const { rows, total } = await findCampaigns(supabase, query);
  return buildPage(rows, total, query);
}

export async function getCampaign(supabase: AuthClient, id: string): Promise<CampaignDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Campaign not found.");
  const detail = await findCampaignDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Campaign not found.");
  return detail;
}

export async function createCampaign(
  auth: AuthContext,
  input: CreateCampaignInput,
  request: RequestLike,
): Promise<CampaignDetail> {
  const { actor_ids, ...columns } = input;
  const { supabase } = auth;
  await assertLinkTargetsExist(supabase, "threat_actors", actor_ids ?? [], "actor_ids");

  const row = await insertCampaign(supabase, columns);
  if (actor_ids) {
    try {
      await setCampaignActors(supabase, row.id, actor_ids);
    } catch (error) {
      await deleteCampaignRow(supabase, row.id).catch(() => null);
      throw error;
    }
  }

  await audit(auth, request, "campaign.created", "campaign", row.id, {
    name: row.name,
    status: row.status,
    origin: row.origin,
    actors: actor_ids?.length ?? 0,
  });
  return getCampaign(supabase, row.id);
}

export async function updateCampaign(
  auth: AuthContext,
  id: string,
  input: UpdateCampaignInput,
  request: RequestLike,
): Promise<CampaignDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Campaign not found.");
  const { actor_ids, ...columns } = input;
  const { supabase } = auth;

  const current = await findCampaignRow(supabase, id);
  if (!current) throw apiErrors.notFound("Campaign not found.");
  await assertLinkTargetsExist(supabase, "threat_actors", actor_ids ?? [], "actor_ids");

  if (Object.keys(columns).length > 0) {
    const updated = await updateCampaignRow(supabase, id, columns);
    if (!updated) throw apiErrors.notFound("Campaign not found.");
  }
  if (actor_ids) await setCampaignActors(supabase, id, actor_ids);

  await audit(auth, request, "campaign.updated", "campaign", id, {
    name: columns.name ?? current.name,
    fields: Object.keys(columns),
    links: actor_ids ? ["actors"] : [],
  });
  return getCampaign(supabase, id);
}

export async function deleteCampaign(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isEntityId(id)) throw apiErrors.notFound("Campaign not found.");
  const removed = await deleteCampaignRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Campaign not found.");
  await audit(auth, request, "campaign.deleted", "campaign", id, {
    name: removed.name,
    origin: removed.origin,
  });
}

// --- Malware --------------------------------------------------------------------------------------

export async function listMalware(
  supabase: AuthClient,
  query: MalwareListQuery,
): Promise<Page<MalwareListItem>> {
  const { rows, total } = await findMalwareFamilies(supabase, query);
  return buildPage(rows, total, query);
}

export const listMalwareTypes = (supabase: AuthClient): Promise<string[]> =>
  findMalwareTypes(supabase);

export async function getMalware(supabase: AuthClient, id: string): Promise<MalwareDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Malware family not found.");
  const detail = await findMalwareDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Malware family not found.");
  return detail;
}

export async function createMalware(
  auth: AuthContext,
  input: CreateMalwareInput,
  request: RequestLike,
): Promise<MalwareDetail> {
  const { actor_ids, ...columns } = input;
  const { supabase } = auth;
  await assertLinkTargetsExist(supabase, "threat_actors", actor_ids ?? [], "actor_ids");

  const row = await insertMalware(supabase, columns);
  if (actor_ids) {
    try {
      await setMalwareActors(supabase, row.id, actor_ids);
    } catch (error) {
      await deleteMalwareRow(supabase, row.id).catch(() => null);
      throw error;
    }
  }

  await audit(auth, request, "malware.created", "malware", row.id, {
    name: row.name,
    origin: row.origin,
    actors: actor_ids?.length ?? 0,
  });
  return getMalware(supabase, row.id);
}

export async function updateMalware(
  auth: AuthContext,
  id: string,
  input: UpdateMalwareInput,
  request: RequestLike,
): Promise<MalwareDetail> {
  if (!isEntityId(id)) throw apiErrors.notFound("Malware family not found.");
  const { actor_ids, ...columns } = input;
  const { supabase } = auth;

  const current = await findMalwareRow(supabase, id);
  if (!current) throw apiErrors.notFound("Malware family not found.");
  await assertLinkTargetsExist(supabase, "threat_actors", actor_ids ?? [], "actor_ids");

  if (Object.keys(columns).length > 0) {
    const updated = await updateMalwareRow(supabase, id, columns);
    if (!updated) throw apiErrors.notFound("Malware family not found.");
  }
  if (actor_ids) await setMalwareActors(supabase, id, actor_ids);

  await audit(auth, request, "malware.updated", "malware", id, {
    name: columns.name ?? current.name,
    fields: Object.keys(columns),
    links: actor_ids ? ["actors"] : [],
  });
  return getMalware(supabase, id);
}

export async function deleteMalware(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isEntityId(id)) throw apiErrors.notFound("Malware family not found.");
  const removed = await deleteMalwareRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Malware family not found.");
  await audit(auth, request, "malware.deleted", "malware", id, {
    name: removed.name,
    origin: removed.origin,
  });
}

// --- MITRE ATT&CK techniques (read-only reference data) ---------------------------------------------

export async function listTechniques(
  supabase: AuthClient,
  query: TechniqueListQuery,
): Promise<Page<MitreTechnique>> {
  const { rows, total } = await findTechniques(supabase, query);
  return buildPage(rows, total, query);
}

export const listTactics = (supabase: AuthClient): Promise<string[]> => findTactics(supabase);

export async function getTechnique(supabase: AuthClient, id: string): Promise<TechniqueDetail> {
  const techniqueId = parseTechniqueId(id);
  if (!techniqueId) throw apiErrors.notFound("Technique not found.");
  const detail = await findTechniqueDetail(supabase, techniqueId);
  if (!detail) throw apiErrors.notFound("Technique not found.");
  return detail;
}

// --- Forms ----------------------------------------------------------------------------------------

export const getLinkOptions = (supabase: AuthClient): Promise<LinkOptions> =>
  findLinkOptions(supabase);
