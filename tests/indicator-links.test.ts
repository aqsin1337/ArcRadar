import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { addRelationshipSchema, setIndicatorLinksSchema } from "@/lib/indicators/schema";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  deleteIndicatorRow: vi.fn(),
  deleteRelationshipRow: vi.fn(),
  findAllTags: vi.fn(),
  findIndicatorDetail: vi.fn(),
  findIndicatorIdentity: vi.fn(),
  findIndicators: vi.fn(),
  findTagsByIndicator: vi.fn(),
  insertIndicator: vi.fn(),
  insertRelationship: vi.fn(),
  replaceIndicatorLinks: vi.fn(),
  replaceIndicatorTags: vi.fn(),
  updateIndicatorRow: vi.fn(),
}));
const threatIntel = vi.hoisted(() => ({ assertLinkTargetsExist: vi.fn() }));
const audit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/indicators/repository", () => repo);
vi.mock("@/lib/threat-intel/repository", () => threatIntel);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const { addRelationship, removeRelationship, setIndicatorLinks } =
  await import("@/lib/indicators/service");

const ID = "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d";
const OTHER = "5c1f7d20-8d4b-4a53-8a1e-2b7f9c0d1e3f";
const ACTOR = "9a3c2e10-1b7d-4e6f-a0c4-5d8e7f6a4b3c";
const CAMPAIGN = "7e2b1c90-4a6d-4f3e-b8a5-0c9d8e7f6a5b";
const RELATIONSHIP = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const request = { headers: new Headers() };

const auth = (): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: "analyst@arcradar.test" },
  profile: { display_name: "Analyst", role: "analyst" },
  permissions: permissionsForRole("analyst"),
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

describe("indicator link schemas", () => {
  it("set the three link lists, each replacing its whole set, with duplicates dropped", () => {
    expect(setIndicatorLinksSchema.parse({ actor_ids: [ACTOR, ACTOR], malware_ids: [] })).toEqual({
      actor_ids: [ACTOR],
      malware_ids: [],
    });
  });

  it("accept each kind of link on its own", () => {
    expect(setIndicatorLinksSchema.parse({ campaign_ids: [CAMPAIGN] })).toEqual({
      campaign_ids: [CAMPAIGN],
    });
    expect(setIndicatorLinksSchema.parse({ malware_ids: [OTHER] })).toEqual({
      malware_ids: [OTHER],
    });
  });

  it("need at least one list, know nothing else and check every id", () => {
    expect(setIndicatorLinksSchema.safeParse({}).success).toBe(false);
    expect(setIndicatorLinksSchema.safeParse({ actor_ids: [ACTOR], origin: "demo" }).success).toBe(
      false,
    );
    expect(setIndicatorLinksSchema.safeParse({ campaign_ids: ["nope"] }).success).toBe(false);
  });

  it("describe a relationship by its target and one of the known kinds", () => {
    expect(addRelationshipSchema.parse({ target_id: OTHER, relationship: "resolves_to" })).toEqual({
      target_id: OTHER,
      relationship: "resolves_to",
    });
    expect(
      addRelationshipSchema.safeParse({ target_id: OTHER, relationship: "likes" }).success,
    ).toBe(false);
    expect(
      addRelationshipSchema.safeParse({ target_id: "nope", relationship: "related_to" }).success,
    ).toBe(false);
    expect(addRelationshipSchema.safeParse({ relationship: "related_to" }).success).toBe(false);
    expect(
      addRelationshipSchema.safeParse({
        target_id: OTHER,
        relationship: "related_to",
        source_id: ID,
      }).success,
    ).toBe(false);
  });
});

describe("setIndicatorLinks", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findIndicatorIdentity.mockResolvedValue({
      id: ID,
      type: "domain",
      value: "login.example",
    });
    repo.findIndicatorDetail.mockResolvedValue({ id: ID });
  });

  it("checks the targets, replaces the sets, and audits how many links each kind has now", async () => {
    await setIndicatorLinks(auth(), ID, { actor_ids: [ACTOR], campaign_ids: [] }, request);

    expect(threatIntel.assertLinkTargetsExist).toHaveBeenCalledWith(
      expect.anything(),
      "threat_actors",
      [ACTOR],
      "actor_ids",
    );
    expect(repo.replaceIndicatorLinks).toHaveBeenCalledWith(expect.anything(), ID, {
      actors: [ACTOR],
      campaigns: [],
      malware: undefined, // left alone
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "indicator.links_updated",
        entityId: ID,
        metadata: {
          type: "domain",
          value: "login.example",
          threat_actors: 1,
          campaigns: 0,
          malware: null,
        },
      }),
      request,
    );
  });

  it("writes nothing when a target does not exist", async () => {
    threatIntel.assertLinkTargetsExist.mockRejectedValue(
      new ApiError(422, "VALIDATION_ERROR", "missing"),
    );
    expect(
      await failureOf(setIndicatorLinks(auth(), ID, { actor_ids: [ACTOR] }, request)),
    ).toMatchObject({ status: 422 });
    expect(repo.replaceIndicatorLinks).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("answers 404 for a malformed or unknown indicator", async () => {
    expect(
      await failureOf(setIndicatorLinks(auth(), "nope", { actor_ids: [] }, request)),
    ).toMatchObject({ status: 404 });
    repo.findIndicatorIdentity.mockResolvedValue(null);
    expect(
      await failureOf(setIndicatorLinks(auth(), ID, { actor_ids: [] }, request)),
    ).toMatchObject({ status: 404 });
  });
});

describe("addRelationship and removeRelationship", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.findIndicatorIdentity.mockImplementation(async (_supabase, id: string) =>
      id === ID
        ? { id, type: "domain", value: "login.example" }
        : id === OTHER
          ? { id, type: "ipv4", value: "203.0.113.9" }
          : null,
    );
    repo.findIndicatorDetail.mockResolvedValue({ id: ID });
    repo.insertRelationship.mockResolvedValue({ id: RELATIONSHIP });
  });

  it("relates this indicator (the source) to another and audits both values", async () => {
    await addRelationship(auth(), ID, { target_id: OTHER, relationship: "resolves_to" }, request);

    expect(repo.insertRelationship).toHaveBeenCalledWith(
      expect.anything(),
      ID,
      OTHER,
      "resolves_to",
    );
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "indicator.relationship_added",
        entityId: ID,
        metadata: {
          relationship_id: RELATIONSHIP,
          relationship: "resolves_to",
          source: "login.example",
          target: "203.0.113.9",
        },
      }),
      request,
    );
  });

  it("refuses an indicator related to itself (422) and a target that does not exist (422)", async () => {
    const self = await failureOf(
      addRelationship(auth(), ID, { target_id: ID, relationship: "related_to" }, request),
    );
    expect(self).toMatchObject({ status: 422 });

    const missing = await failureOf(
      addRelationship(auth(), ID, { target_id: ACTOR, relationship: "related_to" }, request),
    );
    expect(missing).toMatchObject({ status: 422 });
    expect(repo.insertRelationship).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("answers 404 when the source indicator is not there", async () => {
    repo.findIndicatorIdentity.mockResolvedValue(null);
    expect(
      await failureOf(
        addRelationship(auth(), ID, { target_id: OTHER, relationship: "related_to" }, request),
      ),
    ).toMatchObject({ status: 404 });
  });

  it("removes a relationship that involves the indicator and audits it", async () => {
    repo.deleteRelationshipRow.mockResolvedValue({
      id: RELATIONSHIP,
      relationship: "resolves_to",
      source_indicator_id: ID,
      target_indicator_id: OTHER,
    });
    await removeRelationship(auth(), ID, RELATIONSHIP, request);

    expect(repo.deleteRelationshipRow).toHaveBeenCalledWith(expect.anything(), ID, RELATIONSHIP);
    expect(audit.mock.calls[0][0]).toMatchObject({
      action: "indicator.relationship_removed",
      metadata: {
        relationship_id: RELATIONSHIP,
        relationship: "resolves_to",
        source_id: ID,
        target_id: OTHER,
      },
    });
  });

  it("answers 404 for a relationship that is not this indicator's, or an id that is not one", async () => {
    repo.deleteRelationshipRow.mockResolvedValue(null);
    expect(await failureOf(removeRelationship(auth(), ID, RELATIONSHIP, request))).toMatchObject({
      status: 404,
    });
    expect(audit).not.toHaveBeenCalled();

    repo.deleteRelationshipRow.mockClear();
    expect(await failureOf(removeRelationship(auth(), ID, "nope", request))).toMatchObject({
      status: 404,
    });
    expect(repo.deleteRelationshipRow).not.toHaveBeenCalled();
  });
});
