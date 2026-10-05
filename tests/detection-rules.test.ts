import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  deleteDetectionRuleRow: vi.fn(),
  findDetectionRules: vi.fn(),
  insertDetectionRule: vi.fn(),
  updateDetectionRuleRow: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock("@/lib/detection-rules/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const {
  createDetectionRule,
  deleteDetectionRule,
  isRuleId,
  listDetectionRules,
  updateDetectionRule,
} = await import("@/lib/detection-rules/service");

const request = { headers: new Headers() };
const RULE_ID = 100010;

const auth = (role: "admin" | "soc_l2" | "viewer" = "admin"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: `${role}@arcradar.test` },
  profile: { display_name: role, role },
  permissions: permissionsForRole(role),
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

beforeEach(() => {
  vi.clearAllMocks();
  audit.mockResolvedValue(true);
});

describe("isRuleId", () => {
  it("accepts only integers in the reserved 100000-999999 band", () => {
    expect(isRuleId(100000)).toBe(true);
    expect(isRuleId(999999)).toBe(true);
    expect(isRuleId(100010)).toBe(true);
    expect(isRuleId(99999)).toBe(false);
    expect(isRuleId(1000000)).toBe(false);
    expect(isRuleId(100010.5)).toBe(false);
    expect(isRuleId(Number.NaN)).toBe(false);
  });
});

describe("the rule catalog", () => {
  it("lists rules from the repository", async () => {
    repo.findDetectionRules.mockResolvedValue([{ id: RULE_ID }]);
    const rules = await listDetectionRules({} as AuthClient);
    expect(rules).toEqual([{ id: RULE_ID }]);
  });

  it("creates and audits a rule", async () => {
    repo.insertDetectionRule.mockResolvedValue({ id: RULE_ID, name: "fx rule" });
    const created = await createDetectionRule(
      auth(),
      {
        id: RULE_ID,
        name: "fx rule",
        conditions: [{ field: "title", op: "contains", value: "ransom" }],
      },
      request,
    );
    expect(created.id).toBe(RULE_ID);
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({
      action: "detection_rule.created",
      entityId: String(RULE_ID),
    });
  });

  it("updates a rule and audits which fields changed", async () => {
    repo.updateDetectionRuleRow.mockResolvedValue({ id: RULE_ID, name: "fx renamed" });
    await updateDetectionRule(auth(), RULE_ID, { name: "fx renamed" }, request);
    expect(repo.updateDetectionRuleRow).toHaveBeenCalledWith(expect.anything(), RULE_ID, {
      name: "fx renamed",
    });
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({
      action: "detection_rule.updated",
      metadata: expect.objectContaining({ fields: ["name"] }),
    });
  });

  it("deletes a rule and audits it", async () => {
    repo.deleteDetectionRuleRow.mockResolvedValue({ id: RULE_ID, name: "fx rule" });
    await deleteDetectionRule(auth(), RULE_ID, request);
    expect(audit.mock.calls.at(-1)?.[0]).toMatchObject({ action: "detection_rule.deleted" });
  });

  it("404s an id outside the reserved band without ever touching the repository", async () => {
    expect(await failureOf(updateDetectionRule(auth(), 1, { name: "x" }, request))).toMatchObject({
      status: 404,
    });
    expect(repo.updateDetectionRuleRow).not.toHaveBeenCalled();

    expect(await failureOf(deleteDetectionRule(auth(), 1, request))).toMatchObject({ status: 404 });
    expect(repo.deleteDetectionRuleRow).not.toHaveBeenCalled();
  });

  it("404s updating or deleting a rule the repository does not find", async () => {
    repo.updateDetectionRuleRow.mockResolvedValue(null);
    expect(
      await failureOf(updateDetectionRule(auth(), RULE_ID, { name: "x" }, request)),
    ).toMatchObject({ status: 404 });

    repo.deleteDetectionRuleRow.mockResolvedValue(null);
    expect(await failureOf(deleteDetectionRule(auth(), RULE_ID, request))).toMatchObject({
      status: 404,
    });
  });
});
