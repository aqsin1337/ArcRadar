import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";
import {
  actorListQuerySchema,
  campaignListQuerySchema,
  createActorSchema,
  createCampaignSchema,
  createMalwareSchema,
  malwareListQuerySchema,
  techniqueIdSchema,
  techniqueListQuerySchema,
  updateActorSchema,
  updateCampaignSchema,
  updateMalwareSchema,
} from "@/lib/threat-intel/schema";
import { actorList, campaignList, malwareList, techniqueList } from "@/lib/threat-intel/url";

const repo = vi.hoisted(() => ({
  assertLinkTargetsExist: vi.fn(),
  deleteActorRow: vi.fn(),
  deleteCampaignRow: vi.fn(),
  deleteMalwareRow: vi.fn(),
  findActorDetail: vi.fn(),
  findActorRow: vi.fn(),
  findActors: vi.fn(),
  findCampaignDetail: vi.fn(),
  findCampaignRow: vi.fn(),
  findCampaigns: vi.fn(),
  findLinkOptions: vi.fn(),
  findMalwareDetail: vi.fn(),
  findMalwareFamilies: vi.fn(),
  findMalwareRow: vi.fn(),
  findMalwareTypes: vi.fn(),
  findTactics: vi.fn(),
  findTechniqueDetail: vi.fn(),
  findTechniques: vi.fn(),
  insertActor: vi.fn(),
  insertCampaign: vi.fn(),
  insertMalware: vi.fn(),
  setActorLinks: vi.fn(),
  setCampaignActors: vi.fn(),
  setMalwareActors: vi.fn(),
  updateActorRow: vi.fn(),
  updateCampaignRow: vi.fn(),
  updateMalwareRow: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/threat-intel/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const {
  createActor,
  createCampaign,
  createMalware,
  deleteActor,
  deleteCampaign,
  deleteMalware,
  getActor,
  getTechnique,
  isEntityId,
  listActors,
  parseTechniqueId,
  updateActor,
  updateCampaign,
  updateMalware,
} = await import("@/lib/threat-intel/service");

const ID = "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d";
const MALWARE = "5c1f7d20-8d4b-4a53-8a1e-2b7f9c0d1e3f";
const CAMPAIGN = "9a3c2e10-1b7d-4e6f-a0c4-5d8e7f6a4b3c";
const ACTOR = "7e2b1c90-4a6d-4f3e-b8a5-0c9d8e7f6a5b";
const ADMIN = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const request = { headers: new Headers() };

const auth = (): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: ADMIN, email: "admin@arcradar.test" },
  profile: { display_name: "Admin", role: "admin" },
  permissions: permissionsForRole("admin"),
});

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected the call to fail");
}

describe("threat intelligence list queries", () => {
  it("default to the order each list reads best in", () => {
    expect(actorListQuerySchema.parse({})).toMatchObject({ sort: "name", order: "asc", page: 1 });
    expect(campaignListQuerySchema.parse({})).toMatchObject({ sort: "last_seen", order: "desc" });
    expect(malwareListQuerySchema.parse({})).toMatchObject({ sort: "name", order: "asc" });
    expect(techniqueListQuerySchema.parse({})).toMatchObject({ sort: "id", order: "asc" });
  });

  it("treat blanks as not set and reject values that are not in the lists", () => {
    expect(actorListQuerySchema.parse({ q: "", origin: "" })).toMatchObject({
      q: undefined,
      origin: undefined,
    });
    expect(actorListQuerySchema.safeParse({ origin: "imported" }).success).toBe(false);
    expect(campaignListQuerySchema.safeParse({ status: "finished" }).success).toBe(false);
    expect(campaignListQuerySchema.parse({ status: "dormant" }).status).toBe("dormant");
    expect(malwareListQuerySchema.safeParse({ sort: "platforms" }).success).toBe(false);
    expect(techniqueListQuerySchema.parse({ tactic: "Initial Access" }).tactic).toBe(
      "Initial Access",
    );
  });
});

describe("threat actor bodies", () => {
  it("clean up text and lists: blanks become null, duplicates and empty items go", () => {
    const parsed = createActorSchema.parse({
      name: "  Crimson Harbor ",
      aliases: ["DEMO-FIN-01", "demo-fin-01", " ", "CH"],
      description: "",
      motivation: "  Financial gain ",
      attribution_country: "",
      target_industries: ["Finance", "finance"],
      malware_ids: [MALWARE, MALWARE],
      technique_ids: ["T1566", "T1566", "T1078.001"],
    });
    expect(parsed).toMatchObject({
      name: "Crimson Harbor",
      aliases: ["DEMO-FIN-01", "CH"],
      description: null,
      motivation: "Financial gain",
      attribution_country: null,
      target_industries: ["Finance"],
      malware_ids: [MALWARE],
      technique_ids: ["T1566", "T1078.001"],
    });
  });

  it("are strict: origin, owner and ids are not the client's to set", () => {
    for (const extra of [{ origin: "external" }, { created_by: ADMIN }, { id: ID }]) {
      expect(createActorSchema.safeParse({ name: "x", ...extra }).success).toBe(false);
      expect(updateActorSchema.safeParse({ name: "x", ...extra }).success).toBe(false);
    }
    expect(createActorSchema.safeParse({ name: "  " }).success).toBe(false);
  });

  it("check technique and record ids", () => {
    expect(createActorSchema.safeParse({ name: "x", technique_ids: ["T15"] }).success).toBe(false);
    expect(createActorSchema.safeParse({ name: "x", technique_ids: ["t1566"] }).success).toBe(
      false,
    );
    expect(createActorSchema.safeParse({ name: "x", malware_ids: ["nope"] }).success).toBe(false);
  });

  it("refuse a last-seen date before the first-seen date, and let an update clear a date with null", () => {
    const early = "2026-01-01T00:00:00.000Z";
    const late = "2026-06-01T00:00:00.000Z";
    const result = createActorSchema.safeParse({ name: "x", first_seen: late, last_seen: early });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]).toMatchObject({ path: ["last_seen"] });

    expect(updateActorSchema.parse({ first_seen: null })).toEqual({ first_seen: null });
    expect(updateActorSchema.safeParse({ first_seen: "yesterday" }).success).toBe(false);
  });

  it("need something to update; an empty link list is a real change (it clears the links)", () => {
    expect(updateActorSchema.safeParse({}).success).toBe(false);
    expect(updateActorSchema.parse({ malware_ids: [] })).toEqual({ malware_ids: [] });
  });
});

describe("campaign and malware bodies", () => {
  it("accept a status from the list only", () => {
    expect(createCampaignSchema.parse({ name: "Winter Ledger", status: "concluded" }).status).toBe(
      "concluded",
    );
    expect(createCampaignSchema.safeParse({ name: "x", status: "finished" }).success).toBe(false);
    expect(createCampaignSchema.safeParse({ name: "x", origin: "demo" }).success).toBe(false);
    expect(updateCampaignSchema.safeParse({}).success).toBe(false);
    expect(updateCampaignSchema.parse({ actor_ids: [ACTOR, ACTOR] })).toEqual({
      actor_ids: [ACTOR],
    });
  });

  it("keep platforms tidy and never take an origin", () => {
    expect(
      createMalwareSchema.parse({
        name: "NightLoader",
        platforms: ["Windows", "windows", ""],
        malware_type: " Loader ",
      }),
    ).toMatchObject({ platforms: ["Windows"], malware_type: "Loader" });
    expect(createMalwareSchema.safeParse({ name: "x", origin: "external" }).success).toBe(false);
    expect(updateMalwareSchema.safeParse({}).success).toBe(false);
    expect(updateMalwareSchema.parse({ malware_type: "" })).toEqual({ malware_type: null });
  });
});

describe("technique ids", () => {
  it("are normalized to upper case and must look like ATT&CK ids", () => {
    expect(techniqueIdSchema.parse(" t1566 ")).toBe("T1566");
    expect(techniqueIdSchema.parse("t1078.001")).toBe("T1078.001");
    for (const bad of ["T156", "T15660", "1566", "T1566.1", "T1566/../x", ""]) {
      expect(techniqueIdSchema.safeParse(bad).success).toBe(false);
    }
    expect(parseTechniqueId("t1059")).toBe("T1059");
    expect(parseTechniqueId("nope")).toBeNull();
  });

  it("recognize record ids", () => {
    expect(isEntityId(ID)).toBe(true);
    expect(isEntityId("T1566")).toBe(false);
  });
});

describe("threat intelligence list addresses", () => {
  it("leave the default sort out and keep filters, sort and page", () => {
    expect(actorList.href({})).toBe("/threat-actors");
    expect(actorList.href({ sort: "name", order: "asc", page: 1 })).toBe("/threat-actors");
    expect(
      actorList.href(
        { q: "harbor", origin: "demo" },
        { sort: "last_seen", order: "desc", page: 2 },
      ),
    ).toBe("/threat-actors?q=harbor&origin=demo&sort=last_seen&order=desc&page=2");
    expect(campaignList.href({ status: "active" })).toBe("/campaigns?status=active");
    expect(campaignList.href({ sort: "last_seen", order: "desc" })).toBe("/campaigns");
    expect(malwareList.href({ type: "Loader" }, { sort: "name", order: "desc" })).toBe(
      "/malware?type=Loader&sort=name&order=desc",
    );
    expect(techniqueList.href({ tactic: "Initial Access" })).toBe("/mitre?tactic=Initial+Access");
  });

  it("say whether a filter is active (sorting and paging do not count)", () => {
    expect(actorList.hasActive({ sort: "last_seen", page: 3 })).toBe(false);
    expect(campaignList.hasActive({ status: "dormant" })).toBe(true);
    expect(techniqueList.hasActive({ q: "" })).toBe(false);
  });
});

describe("threat actors", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findActorDetail.mockResolvedValue({ id: ID, name: "Crimson Harbor" });
    repo.findActorRow.mockResolvedValue({ id: ID, name: "Crimson Harbor", origin: "local" });
    repo.insertActor.mockResolvedValue({ id: ID, name: "Crimson Harbor", origin: "local" });
    repo.updateActorRow.mockResolvedValue({ id: ID, name: "Crimson Harbor" });
  });

  it("creates the actor, sets its links and audits it as local data", async () => {
    await createActor(
      auth(),
      {
        name: "Crimson Harbor",
        malware_ids: [MALWARE],
        campaign_ids: [],
        technique_ids: ["T1566"],
      },
      request,
    );

    expect(repo.assertLinkTargetsExist).toHaveBeenCalledTimes(3);
    expect(repo.assertLinkTargetsExist).toHaveBeenCalledWith(
      expect.anything(),
      "malware",
      [MALWARE],
      "malware_ids",
    );
    expect(repo.insertActor).toHaveBeenCalledWith(expect.anything(), { name: "Crimson Harbor" });
    expect(repo.setActorLinks).toHaveBeenCalledWith(expect.anything(), ID, {
      malware: [MALWARE],
      campaigns: [],
      techniques: ["T1566"],
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "threat_actor.created",
        entityType: "threat_actor",
        entityId: ID,
        metadata: {
          name: "Crimson Harbor",
          origin: "local",
          malware: 1,
          campaigns: 0,
          techniques: 1,
        },
      }),
      request,
    );
  });

  it("checks every link target before it writes anything", async () => {
    repo.assertLinkTargetsExist.mockRejectedValue(new ApiError(422, "VALIDATION_ERROR", "missing"));
    const error = await failureOf(
      createActor(auth(), { name: "x", malware_ids: [MALWARE] }, request),
    );
    expect(error).toMatchObject({ status: 422 });
    expect(repo.insertActor).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("removes the half-saved actor when its links cannot be set, and reports the failure", async () => {
    repo.setActorLinks.mockRejectedValue(new ApiError(422, "VALIDATION_ERROR", "gone"));
    repo.deleteActorRow.mockResolvedValue({ id: ID });
    const error = await failureOf(
      createActor(auth(), { name: "x", malware_ids: [MALWARE] }, request),
    );

    expect(error).toMatchObject({ status: 422 });
    expect(repo.deleteActorRow).toHaveBeenCalledWith(expect.anything(), ID);
    expect(audit).not.toHaveBeenCalled();
  });

  it("only touches the row when a column changed, and links are replaced only when sent", async () => {
    await updateActor(auth(), ID, { technique_ids: ["T1078"] }, request);
    expect(repo.updateActorRow).not.toHaveBeenCalled();
    expect(repo.setActorLinks).toHaveBeenCalledWith(expect.anything(), ID, {
      malware: undefined,
      campaigns: undefined,
      techniques: ["T1078"],
    });
    expect(audit.mock.calls[0][0].metadata).toEqual({
      name: "Crimson Harbor",
      fields: [],
      links: ["techniques"],
    });

    await updateActor(auth(), ID, { motivation: "Espionage" }, request);
    expect(repo.updateActorRow).toHaveBeenCalledWith(expect.anything(), ID, {
      motivation: "Espionage",
    });
  });

  it("answers 404 for a malformed id, a missing actor, and a delete of something already gone", async () => {
    expect(await failureOf(updateActor(auth(), "nope", { name: "x" }, request))).toMatchObject({
      status: 404,
    });
    repo.findActorRow.mockResolvedValue(null);
    expect(await failureOf(updateActor(auth(), ID, { name: "x" }, request))).toMatchObject({
      status: 404,
    });
    repo.findActorDetail.mockResolvedValue(null);
    expect(await failureOf(getActor({} as AuthClient, ID))).toMatchObject({ status: 404 });
    repo.deleteActorRow.mockResolvedValue(null);
    expect(await failureOf(deleteActor(auth(), ID, request))).toMatchObject({ status: 404 });
  });

  it("audits a deletion with the name and provenance", async () => {
    repo.deleteActorRow.mockResolvedValue({ id: ID, name: "Crimson Harbor", origin: "demo" });
    await deleteActor(auth(), ID, request);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "threat_actor.deleted",
        metadata: { name: "Crimson Harbor", origin: "demo" },
      }),
      request,
    );
  });

  it("pages the list like every other list", async () => {
    repo.findActors.mockResolvedValue({ rows: [{ id: ID }], total: 51 });
    const page = await listActors({} as AuthClient, actorListQuerySchema.parse({ page: 2 }));
    expect(page.pagination).toEqual({ page: 2, page_size: 25, total: 51, total_pages: 3 });
  });
});

describe("campaigns and malware", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findCampaignDetail.mockResolvedValue({ id: CAMPAIGN });
    repo.findCampaignRow.mockResolvedValue({ id: CAMPAIGN, name: "Harbor Lights" });
    repo.insertCampaign.mockResolvedValue({
      id: CAMPAIGN,
      name: "Harbor Lights",
      status: "active",
      origin: "local",
    });
    repo.updateCampaignRow.mockResolvedValue({ id: CAMPAIGN });
    repo.findMalwareDetail.mockResolvedValue({ id: MALWARE });
    repo.findMalwareRow.mockResolvedValue({ id: MALWARE, name: "NightLoader" });
    repo.insertMalware.mockResolvedValue({ id: MALWARE, name: "NightLoader", origin: "local" });
    repo.updateMalwareRow.mockResolvedValue({ id: MALWARE });
  });

  it("creates a campaign without touching links it was not given", async () => {
    await createCampaign(auth(), { name: "Harbor Lights" }, request);
    expect(repo.setCampaignActors).not.toHaveBeenCalled();
    expect(audit.mock.calls[0][0]).toMatchObject({
      action: "campaign.created",
      metadata: { name: "Harbor Lights", status: "active", origin: "local", actors: 0 },
    });
  });

  it("removes a half-saved campaign or malware family when its actors cannot be linked", async () => {
    repo.deleteCampaignRow.mockResolvedValue({ id: CAMPAIGN });
    repo.deleteMalwareRow.mockResolvedValue({ id: MALWARE });
    repo.setCampaignActors.mockRejectedValue(new ApiError(422, "VALIDATION_ERROR", "gone"));
    await failureOf(createCampaign(auth(), { name: "Harbor Lights", actor_ids: [ACTOR] }, request));
    expect(repo.deleteCampaignRow).toHaveBeenCalledWith(expect.anything(), CAMPAIGN);

    repo.setMalwareActors.mockRejectedValue(new ApiError(422, "VALIDATION_ERROR", "gone"));
    await failureOf(createMalware(auth(), { name: "NightLoader", actor_ids: [ACTOR] }, request));
    expect(repo.deleteMalwareRow).toHaveBeenCalledWith(expect.anything(), MALWARE);
    expect(audit).not.toHaveBeenCalled();
  });

  it("replaces the actors of a campaign or malware family only when a list is sent", async () => {
    await updateCampaign(auth(), CAMPAIGN, { status: "dormant" }, request);
    expect(repo.setCampaignActors).not.toHaveBeenCalled();
    expect(repo.updateCampaignRow).toHaveBeenCalledWith(expect.anything(), CAMPAIGN, {
      status: "dormant",
    });

    await updateCampaign(auth(), CAMPAIGN, { actor_ids: [] }, request);
    expect(repo.setCampaignActors).toHaveBeenCalledWith(expect.anything(), CAMPAIGN, []);
    expect(repo.updateCampaignRow).toHaveBeenCalledTimes(1); // nothing to change in the row itself

    await updateMalware(auth(), MALWARE, { actor_ids: [ACTOR] }, request);
    expect(repo.setMalwareActors).toHaveBeenCalledWith(expect.anything(), MALWARE, [ACTOR]);
  });

  it("audits deletions of campaigns and malware with their names", async () => {
    repo.deleteCampaignRow.mockResolvedValue({
      id: CAMPAIGN,
      name: "Harbor Lights",
      origin: "demo",
    });
    repo.deleteMalwareRow.mockResolvedValue({ id: MALWARE, name: "NightLoader", origin: "demo" });
    await deleteCampaign(auth(), CAMPAIGN, request);
    await deleteMalware(auth(), MALWARE, request);
    expect(audit.mock.calls.map(([entry]) => [entry.action, entry.metadata.name])).toEqual([
      ["campaign.deleted", "Harbor Lights"],
      ["malware.deleted", "NightLoader"],
    ]);
  });
});

describe("techniques", () => {
  beforeEach(() => vi.resetAllMocks());

  it("answers 404 for an id that cannot be a technique, without asking the database", async () => {
    expect(await failureOf(getTechnique({} as AuthClient, "nope"))).toMatchObject({ status: 404 });
    expect(repo.findTechniqueDetail).not.toHaveBeenCalled();
  });

  it("looks a technique up by its canonical id", async () => {
    repo.findTechniqueDetail.mockResolvedValue({ id: "T1566", actors: [] });
    await getTechnique({} as AuthClient, "t1566");
    expect(repo.findTechniqueDetail).toHaveBeenCalledWith(expect.anything(), "T1566");

    repo.findTechniqueDetail.mockResolvedValue(null);
    expect(await failureOf(getTechnique({} as AuthClient, "T9999"))).toMatchObject({ status: 404 });
  });
});
