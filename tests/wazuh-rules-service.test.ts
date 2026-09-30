import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import { AiProviderError, type AiProvider } from "@/lib/ai/types";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { GithubError, type GithubRepoConfig } from "@/lib/github/contents";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { WazuhRule } from "@/lib/wazuh-rules/types";

const repo = vi.hoisted(() => ({
  deleteWazuhRuleRow: vi.fn(),
  findWazuhRule: vi.fn(),
  findWazuhRules: vi.fn(),
  insertWazuhRule: vi.fn(),
  nextWazuhRuleId: vi.fn(),
  updateWazuhRuleRow: vi.fn(),
}));
const aiService = vi.hoisted(() => ({ getAiAvailability: vi.fn(), defaultDeps: vi.fn() }));
const github = vi.hoisted(() => ({ commitRepoFile: vi.fn() }));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock("@/lib/wazuh-rules/repository", () => repo);
vi.mock("@/lib/ai/service", () => aiService);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/github/contents", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/github/contents")>()),
  commitRepoFile: github.commitRepoFile,
}));

const {
  createWazuhRule,
  deleteWazuhRule,
  generateWazuhRule,
  isWazuhRuleId,
  pushWazuhRule,
  rejectWazuhRule,
  updateWazuhRule,
} = await import("@/lib/wazuh-rules/service");

const request = { headers: new Headers() };
const admin: AuthContext = {
  supabase: {} as AuthClient,
  user: { id: "admin-1", email: "admin@arcradar.test" },
  profile: { display_name: "Admin", role: "admin" },
  permissions: permissionsForRole("admin"),
};

const config: GithubRepoConfig = {
  owner: "aqsin1337",
  repo: "wazuh_rules",
  branch: "main",
  token: "ghp_test",
};

const rule = (patch: Partial<WazuhRule> = {}): WazuhRule => ({
  id: 100120,
  name: "Defender disable attempt",
  description: null,
  level: 12,
  parent_kind: "group",
  parent_value: "windows",
  conditions: [{ field: "win.eventdata.commandLine", op: "contains", value: "Disable" }],
  mitre_ids: ["T1562.001"],
  frequency: null,
  timeframe: null,
  same_fields: [],
  status: "draft",
  source: "manual",
  ai_prompt: null,
  ai_provider: null,
  ai_model: null,
  github_path: null,
  github_commit: null,
  pushed_at: null,
  pushed_by: null,
  origin: "local",
  changed_since_push: false,
  rejected_at: null,
  reject_reason: null,
  created_by_name: "Admin",
  created_at: "2026-09-30T10:00:00Z",
  updated_at: "2026-09-30T10:00:00Z",
  triggers: 0,
  last_triggered: null,
  xml: "<group/>\n",
  ...patch,
});

const deps = (over: Partial<Parameters<typeof pushWazuhRule>[3]> = {}) => ({
  ai: aiService.defaultDeps,
  githubConfig: () => config,
  githubTimeoutMs: 1000,
  audit,
  ...over,
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

const validDraft = {
  name: "Defender disable attempt",
  description: "Turns off real-time protection.",
  level: 12,
  parent_kind: "group",
  parent_value: "windows",
  conditions: [{ field: "win.eventdata.commandLine", op: "contains", value: "Disable" }],
  mitre_ids: ["T1562.001"],
};

function aiSetup(complete: AiProvider["complete"], ready = true) {
  const provider: AiProvider = { info: { id: "groq", name: "Groq" }, complete };
  aiService.getAiAvailability.mockResolvedValue({
    ready,
    active_provider: ready ? "groq" : null,
    active_model: null,
  });
  aiService.defaultDeps.mockReturnValue({
    registry: new Map([["groq", provider]]),
    timeoutMs: 1000,
    audit,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  audit.mockResolvedValue(true);
  repo.insertWazuhRule.mockImplementation(async (_s, row) =>
    rule({ ...row } as Partial<WazuhRule>),
  );
  repo.nextWazuhRuleId.mockResolvedValue(100101);
});

describe("isWazuhRuleId", () => {
  it("accepts the range and refuses everything else", () => {
    expect(isWazuhRuleId(100100)).toBe(true);
    expect(isWazuhRuleId(999999)).toBe(true);
    expect(isWazuhRuleId(100001)).toBe(false);
    expect(isWazuhRuleId(1.5)).toBe(false);
    expect(isWazuhRuleId(Number.NaN)).toBe(false);
  });
});

describe("createWazuhRule", () => {
  it("takes the next free id when none is given, stores a manual draft and audits it", async () => {
    await createWazuhRule(
      admin,
      { ...validDraft, parent_kind: "group", mitre_ids: [] } as never,
      request,
      deps(),
    );
    const row = repo.insertWazuhRule.mock.calls[0][1];
    expect(row).toMatchObject({ id: 100101, source: "manual" });
    expect(row.status).toBeUndefined();
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "wazuh_rule.created", entityId: "100101" }),
      request,
    );
  });

  it("keeps an id the person chose", async () => {
    await createWazuhRule(admin, { ...validDraft, id: 100500 } as never, request, deps());
    expect(repo.nextWazuhRuleId).not.toHaveBeenCalled();
    expect(repo.insertWazuhRule.mock.calls[0][1].id).toBe(100500);
  });
});

describe("generateWazuhRule", () => {
  it("stores the AI's valid draft as an ai-sourced draft, with the prompt and model, and audits it", async () => {
    const complete = vi.fn().mockResolvedValue({ data: validDraft, model: "openai/gpt-oss-120b" });
    aiSetup(complete);
    const created = await generateWazuhRule(
      admin,
      "Detect Defender being disabled",
      request,
      deps(),
    );

    expect(complete).toHaveBeenCalledTimes(1);
    expect(repo.insertWazuhRule.mock.calls[0][1]).toMatchObject({
      id: 100101,
      source: "ai",
      ai_prompt: "Detect Defender being disabled",
      ai_provider: "groq",
      ai_model: "openai/gpt-oss-120b",
    });
    expect(created.source).toBe("ai");
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "wazuh_rule.generated" }),
      request,
    );
  });

  it("refuses a draft that breaks a rule (an unsafe regex) and stores nothing", async () => {
    aiSetup(
      vi.fn().mockResolvedValue({
        data: {
          ...validDraft,
          conditions: [{ field: "win.eventdata.commandLine", op: "regex", value: "(a+)+" }],
        },
        model: "m",
      }),
    );
    const error = await failureOf(
      generateWazuhRule(admin, "Detect something odd", request, deps()),
    );
    expect(error.status).toBe(503);
    expect(repo.insertWazuhRule).not.toHaveBeenCalled();
  });

  it("refuses an id, a status or an XML fragment the model tries to add on its own", async () => {
    // Extra keys are ignored by the AI schema, never copied into the row.
    aiSetup(
      vi.fn().mockResolvedValue({
        data: { ...validDraft, id: 100999, status: "pushed", xml: "<active-response/>" },
        model: "m",
      }),
    );
    await generateWazuhRule(admin, "Detect something odd", request, deps());
    const row = repo.insertWazuhRule.mock.calls[0][1];
    expect(row.id).toBe(100101);
    expect(row.status).toBeUndefined();
    expect(JSON.stringify(row)).not.toContain("active-response");
  });

  it("reports 503 when no provider is ready and never calls one", async () => {
    const complete = vi.fn();
    aiSetup(complete, false);
    const error = await failureOf(
      generateWazuhRule(admin, "Detect something odd", request, deps()),
    );
    expect(error.status).toBe(503);
    expect(complete).not.toHaveBeenCalled();
  });

  it("maps a provider rate limit to 429 and other failures to 503", async () => {
    aiSetup(vi.fn().mockRejectedValue(new AiProviderError("rate_limited", "slow down", 30)));
    expect(
      (await failureOf(generateWazuhRule(admin, "Detect something odd", request, deps()))).status,
    ).toBe(429);

    aiSetup(vi.fn().mockRejectedValue(new AiProviderError("timeout", "too slow")));
    expect(
      (await failureOf(generateWazuhRule(admin, "Detect something odd", request, deps()))).status,
    ).toBe(503);
  });
});

describe("updateWazuhRule", () => {
  it("marks a pushed rule as changed since the push", async () => {
    repo.findWazuhRule.mockResolvedValue(rule({ status: "pushed", github_path: "rules/x.xml" }));
    repo.updateWazuhRuleRow.mockImplementation(async (_s, _id, patch) =>
      rule({ ...patch } as never),
    );
    await updateWazuhRule(admin, 100120, { level: 9 }, request, deps());
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toMatchObject({
      level: 9,
      changed_since_push: true,
    });
  });

  it("brings a rejected rule back to a draft", async () => {
    repo.findWazuhRule.mockResolvedValue(rule({ status: "rejected" }));
    repo.updateWazuhRuleRow.mockImplementation(async (_s, _id, patch) =>
      rule({ ...patch } as never),
    );
    await updateWazuhRule(admin, 100120, { level: 9 }, request, deps());
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toMatchObject({
      status: "draft",
      rejected_at: null,
      reject_reason: null,
    });
  });

  it("does not touch a plain draft's status", async () => {
    repo.findWazuhRule.mockResolvedValue(rule());
    repo.updateWazuhRuleRow.mockImplementation(async (_s, _id, patch) =>
      rule({ ...patch } as never),
    );
    await updateWazuhRule(admin, 100120, { level: 9 }, request, deps());
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toEqual({ level: 9 });
  });

  it("answers 404 for an unknown or out-of-range id", async () => {
    repo.findWazuhRule.mockResolvedValue(null);
    expect(
      (await failureOf(updateWazuhRule(admin, 100120, { level: 9 }, request, deps()))).status,
    ).toBe(404);
    expect((await failureOf(updateWazuhRule(admin, 5, { level: 9 }, request, deps()))).status).toBe(
      404,
    );
  });
});

describe("rejectWazuhRule", () => {
  it("rejects a draft with a reason", async () => {
    repo.findWazuhRule.mockResolvedValue(rule());
    repo.updateWazuhRuleRow.mockResolvedValue(rule({ status: "rejected" }));
    await rejectWazuhRule(admin, 100120, "too noisy", request, deps());
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toMatchObject({
      status: "rejected",
      reject_reason: "too noisy",
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "wazuh_rule.rejected",
        metadata: expect.objectContaining({ has_reason: true }),
      }),
      request,
    );
  });

  it("refuses a pushed or an already rejected rule", async () => {
    repo.findWazuhRule.mockResolvedValue(rule({ status: "pushed", github_path: "x" }));
    expect((await failureOf(rejectWazuhRule(admin, 100120, null, request, deps()))).status).toBe(
      409,
    );
    repo.findWazuhRule.mockResolvedValue(rule({ status: "rejected" }));
    expect((await failureOf(rejectWazuhRule(admin, 100120, null, request, deps()))).status).toBe(
      409,
    );
    expect(repo.updateWazuhRuleRow).not.toHaveBeenCalled();
  });
});

describe("pushWazuhRule", () => {
  it("commits the generated XML to the expected path and records the push", async () => {
    repo.findWazuhRule.mockResolvedValue(rule());
    github.commitRepoFile.mockResolvedValue({ commitSha: "abc123", unchanged: false });
    repo.updateWazuhRuleRow.mockResolvedValue(rule({ status: "pushed" }));

    await pushWazuhRule(admin, 100120, request, deps());

    const call = github.commitRepoFile.mock.calls[0][0];
    expect(call.path).toBe("rules/arcradar_100120.xml");
    expect(call.content).toBe("<group/>\n");
    expect(call.message).toBe("Add rule 100120: Defender disable attempt");
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toMatchObject({
      status: "pushed",
      github_path: "rules/arcradar_100120.xml",
      github_commit: "abc123",
      changed_since_push: false,
      pushed_by: "admin-1",
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "wazuh_rule.pushed",
        metadata: expect.objectContaining({
          repository: "aqsin1337/wazuh_rules",
          commit: "abc123",
        }),
      }),
      request,
    );
    expect(JSON.stringify(audit.mock.calls)).not.toContain("ghp_test");
  });

  it("says Update when the rule was pushed before, and keeps the last commit when nothing changed", async () => {
    repo.findWazuhRule.mockResolvedValue(
      rule({ status: "pushed", github_path: "rules/arcradar_100120.xml", github_commit: "old" }),
    );
    github.commitRepoFile.mockResolvedValue({ commitSha: null, unchanged: true });
    repo.updateWazuhRuleRow.mockResolvedValue(rule({ status: "pushed" }));

    await pushWazuhRule(admin, 100120, request, deps());

    expect(github.commitRepoFile.mock.calls[0][0].message).toMatch(/^Update rule 100120/);
    expect(repo.updateWazuhRuleRow.mock.calls[0][2]).toMatchObject({ github_commit: "old" });
  });

  it("refuses a rejected rule and pushes nothing", async () => {
    repo.findWazuhRule.mockResolvedValue(rule({ status: "rejected" }));
    expect((await failureOf(pushWazuhRule(admin, 100120, request, deps()))).status).toBe(409);
    expect(github.commitRepoFile).not.toHaveBeenCalled();
  });

  it("reports 503 when GitHub is not configured and leaves the rule a draft", async () => {
    repo.findWazuhRule.mockResolvedValue(rule());
    const error = await failureOf(
      pushWazuhRule(admin, 100120, request, deps({ githubConfig: () => null })),
    );
    expect(error.status).toBe(503);
    expect(github.commitRepoFile).not.toHaveBeenCalled();
    expect(repo.updateWazuhRuleRow).not.toHaveBeenCalled();
  });

  it.each([
    ["auth", 503],
    ["not_found", 503],
    ["unavailable", 503],
    ["timeout", 503],
    ["conflict", 409],
    ["rate_limited", 429],
  ] as const)(
    "maps a GitHub %s failure to %s and leaves the rule untouched",
    async (reason, status) => {
      repo.findWazuhRule.mockResolvedValue(rule());
      github.commitRepoFile.mockRejectedValue(new GithubError(reason, "detail"));
      const error = await failureOf(pushWazuhRule(admin, 100120, request, deps()));
      expect(error.status).toBe(status);
      expect(repo.updateWazuhRuleRow).not.toHaveBeenCalled();
      expect(audit).not.toHaveBeenCalled();
    },
  );
});

describe("deleteWazuhRule", () => {
  it("deletes a draft and audits it", async () => {
    repo.findWazuhRule.mockResolvedValue(rule());
    repo.deleteWazuhRuleRow.mockResolvedValue({ id: 100120, name: "x" });
    await deleteWazuhRule(admin, 100120, request, deps());
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "wazuh_rule.deleted" }),
      request,
    );
  });

  it("refuses a pushed rule: its file lives on GitHub", async () => {
    repo.findWazuhRule.mockResolvedValue(rule({ status: "pushed", github_path: "x" }));
    expect((await failureOf(deleteWazuhRule(admin, 100120, request, deps()))).status).toBe(409);
    expect(repo.deleteWazuhRuleRow).not.toHaveBeenCalled();
  });
});
