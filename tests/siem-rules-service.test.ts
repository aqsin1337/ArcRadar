import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import { AiProviderError, type AiProvider } from "@/lib/ai/types";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { GithubError, type GithubRepoConfig } from "@/lib/github/contents";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { SiemRule } from "@/lib/siem-rules/types";

const repo = vi.hoisted(() => ({
  deleteSiemRuleRow: vi.fn(),
  findSiemRule: vi.fn(),
  findSiemRules: vi.fn(),
  insertSiemRule: vi.fn(),
  nextRuleKey: vi.fn(),
  updateSiemRuleRow: vi.fn(),
}));
const aiService = vi.hoisted(() => ({ getAiAvailability: vi.fn(), defaultDeps: vi.fn() }));
const github = vi.hoisted(() => ({ commitRepoFile: vi.fn() }));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock("@/lib/siem-rules/repository", () => repo);
vi.mock("@/lib/ai/service", () => aiService);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/github/contents", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/github/contents")>()),
  commitRepoFile: github.commitRepoFile,
}));

const {
  createSiemRule,
  deleteSiemRule,
  generateSiemRule,
  pushSiemRule,
  rejectSiemRule,
  updateSiemRule,
} = await import("@/lib/siem-rules/service");

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

const ID = "0b9f8c7e-1111-4222-8333-444455556666";

const spec = {
  index: "main",
  sourcetype: "WinEventLog:Security",
  conditions: [{ field: "EventCode", op: "equals", value: "4625" }],
  threshold: null,
  schedule: "every_5_minutes",
};

const rule = (patch: Partial<SiemRule> = {}): SiemRule => ({
  id: ID,
  siem: "splunk",
  rule_key: "1000",
  name: "Failed logon",
  description: null,
  severity: "medium",
  spec,
  mitre_ids: ["T1110"],
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
  created_at: "2026-10-06T10:00:00Z",
  updated_at: "2026-10-06T10:00:00Z",
  file: { path: "splunk/arcradar_1000.conf", content: "[arcradar_1000]\n" },
  ...patch,
});

const deps = (over: Partial<Parameters<typeof pushSiemRule>[4]> = {}) => ({
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
  name: "Failed logon",
  description: "A failed Windows logon.",
  severity: "medium",
  mitre_ids: ["T1110"],
  spec,
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
  repo.insertSiemRule.mockImplementation(async (_s, row) => rule({ ...row } as Partial<SiemRule>));
  repo.nextRuleKey.mockResolvedValue("1001");
  repo.updateSiemRuleRow.mockImplementation(async (_s, _siem, _id, patch) =>
    rule({ ...patch } as never),
  );
});

describe("createSiemRule", () => {
  it("takes the next free key, stores a manual draft for the right SIEM and audits it", async () => {
    await createSiemRule(admin, "splunk", validDraft as never, request, deps());
    const row = repo.insertSiemRule.mock.calls[0][1];
    expect(row).toMatchObject({ siem: "splunk", rule_key: "1001", source: "manual" });
    expect(row.status).toBeUndefined();
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "siem_rule.created", entityType: "siem_rule" }),
      request,
    );
  });

  it("keeps a key the person chose", async () => {
    await createSiemRule(
      admin,
      "splunk",
      { ...validDraft, rule_key: "brute" } as never,
      request,
      deps(),
    );
    expect(repo.nextRuleKey).not.toHaveBeenCalled();
    expect(repo.insertSiemRule.mock.calls[0][1].rule_key).toBe("brute");
  });
});

describe("generateSiemRule", () => {
  it("stores the AI's valid draft as an ai-sourced draft and audits it", async () => {
    const complete = vi.fn().mockResolvedValue({ data: validDraft, model: "m1" });
    aiSetup(complete);
    await generateSiemRule(admin, "splunk", "Detect a failed logon", request, deps());
    expect(complete).toHaveBeenCalledTimes(1);
    expect(repo.insertSiemRule.mock.calls[0][1]).toMatchObject({
      siem: "splunk",
      rule_key: "1001",
      source: "ai",
      ai_prompt: "Detect a failed logon",
      ai_provider: "groq",
      ai_model: "m1",
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "siem_rule.generated" }),
      request,
    );
  });

  it("refuses a draft with SPL smuggled into a value and stores nothing", async () => {
    aiSetup(
      vi.fn().mockResolvedValue({
        data: {
          ...validDraft,
          spec: {
            ...spec,
            conditions: [{ field: "a | outputlookup x", op: "equals", value: "1" }],
          },
        },
        model: "m",
      }),
    );
    const error = await failureOf(
      generateSiemRule(admin, "splunk", "Detect something odd", request, deps()),
    );
    expect(error.status).toBe(503);
    expect(repo.insertSiemRule).not.toHaveBeenCalled();
  });

  it("ignores an id, status or file the model adds on its own", async () => {
    aiSetup(
      vi.fn().mockResolvedValue({
        data: { ...validDraft, id: ID, status: "pushed", file: "| delete" },
        model: "m",
      }),
    );
    await generateSiemRule(admin, "splunk", "Detect something odd", request, deps());
    const row = repo.insertSiemRule.mock.calls[0][1];
    expect(row.status).toBeUndefined();
    expect(row.id).toBeUndefined();
    expect(JSON.stringify(row)).not.toContain("| delete");
  });

  it("reports 503 when no provider is ready and never calls one", async () => {
    const complete = vi.fn();
    aiSetup(complete, false);
    const error = await failureOf(
      generateSiemRule(admin, "splunk", "Detect something odd", request, deps()),
    );
    expect(error.status).toBe(503);
    expect(complete).not.toHaveBeenCalled();
  });

  it("maps a provider rate limit to 429 and other failures to 503", async () => {
    aiSetup(vi.fn().mockRejectedValue(new AiProviderError("rate_limited", "slow", 30)));
    expect(
      (await failureOf(generateSiemRule(admin, "splunk", "Detect something odd", request, deps())))
        .status,
    ).toBe(429);
    aiSetup(vi.fn().mockRejectedValue(new AiProviderError("timeout", "too slow")));
    expect(
      (await failureOf(generateSiemRule(admin, "splunk", "Detect something odd", request, deps())))
        .status,
    ).toBe(503);
  });
});

describe("updateSiemRule", () => {
  it("marks a pushed rule as changed since the push", async () => {
    repo.findSiemRule.mockResolvedValue(rule({ status: "pushed", github_path: "splunk/x.conf" }));
    await updateSiemRule(admin, "splunk", ID, { severity: "high" }, request, deps());
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toMatchObject({
      severity: "high",
      changed_since_push: true,
    });
  });

  it("brings a rejected rule back to a draft", async () => {
    repo.findSiemRule.mockResolvedValue(rule({ status: "rejected" }));
    await updateSiemRule(admin, "splunk", ID, { severity: "high" }, request, deps());
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toMatchObject({
      status: "draft",
      rejected_at: null,
      reject_reason: null,
    });
  });

  it("does not touch a plain draft's status", async () => {
    repo.findSiemRule.mockResolvedValue(rule());
    await updateSiemRule(admin, "splunk", ID, { severity: "high" }, request, deps());
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toEqual({ severity: "high" });
  });

  it("answers 404 for an unknown or malformed id", async () => {
    repo.findSiemRule.mockResolvedValue(null);
    expect(
      (await failureOf(updateSiemRule(admin, "splunk", ID, { severity: "low" }, request, deps())))
        .status,
    ).toBe(404);
    expect(
      (
        await failureOf(
          updateSiemRule(admin, "splunk", "not-a-uuid", { severity: "low" }, request, deps()),
        )
      ).status,
    ).toBe(404);
    expect(repo.findSiemRule).toHaveBeenCalledTimes(1);
  });
});

describe("rejectSiemRule", () => {
  it("rejects a draft with a reason", async () => {
    repo.findSiemRule.mockResolvedValue(rule());
    await rejectSiemRule(admin, "splunk", ID, "too noisy", request, deps());
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toMatchObject({
      status: "rejected",
      reject_reason: "too noisy",
    });
  });

  it("refuses a pushed or an already rejected rule", async () => {
    repo.findSiemRule.mockResolvedValue(rule({ status: "pushed", github_path: "x" }));
    expect(
      (await failureOf(rejectSiemRule(admin, "splunk", ID, null, request, deps()))).status,
    ).toBe(409);
    repo.findSiemRule.mockResolvedValue(rule({ status: "rejected" }));
    expect(
      (await failureOf(rejectSiemRule(admin, "splunk", ID, null, request, deps()))).status,
    ).toBe(409);
    expect(repo.updateSiemRuleRow).not.toHaveBeenCalled();
  });
});

describe("pushSiemRule", () => {
  it("commits the generated file to its own path and records the push", async () => {
    repo.findSiemRule.mockResolvedValue(rule());
    github.commitRepoFile.mockResolvedValue({ commitSha: "abc123", unchanged: false });
    await pushSiemRule(admin, "splunk", ID, request, deps());
    const call = github.commitRepoFile.mock.calls[0][0];
    expect(call.path).toBe("splunk/arcradar_1000.conf");
    expect(call.content).toBe("[arcradar_1000]\n");
    expect(call.message).toBe("Add Splunk rule 1000: Failed logon");
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toMatchObject({
      status: "pushed",
      github_path: "splunk/arcradar_1000.conf",
      github_commit: "abc123",
      changed_since_push: false,
      pushed_by: "admin-1",
    });
    expect(JSON.stringify(audit.mock.calls)).not.toContain("ghp_test");
  });

  it("says Update for a rule pushed before and keeps the last commit when nothing changed", async () => {
    repo.findSiemRule.mockResolvedValue(
      rule({ status: "pushed", github_path: "splunk/arcradar_1000.conf", github_commit: "old" }),
    );
    github.commitRepoFile.mockResolvedValue({ commitSha: null, unchanged: true });
    await pushSiemRule(admin, "splunk", ID, request, deps());
    expect(github.commitRepoFile.mock.calls[0][0].message).toMatch(/^Update Splunk rule 1000/);
    expect(repo.updateSiemRuleRow.mock.calls[0][3]).toMatchObject({ github_commit: "old" });
  });

  it("refuses a rejected rule and pushes nothing", async () => {
    repo.findSiemRule.mockResolvedValue(rule({ status: "rejected" }));
    expect((await failureOf(pushSiemRule(admin, "splunk", ID, request, deps()))).status).toBe(409);
    expect(github.commitRepoFile).not.toHaveBeenCalled();
  });

  it("reports 503 when GitHub is not configured and leaves the rule a draft", async () => {
    repo.findSiemRule.mockResolvedValue(rule());
    const error = await failureOf(
      pushSiemRule(admin, "splunk", ID, request, deps({ githubConfig: () => null })),
    );
    expect(error.status).toBe(503);
    expect(github.commitRepoFile).not.toHaveBeenCalled();
    expect(repo.updateSiemRuleRow).not.toHaveBeenCalled();
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
      repo.findSiemRule.mockResolvedValue(rule());
      github.commitRepoFile.mockRejectedValue(new GithubError(reason, "detail"));
      const error = await failureOf(pushSiemRule(admin, "splunk", ID, request, deps()));
      expect(error.status).toBe(status);
      expect(repo.updateSiemRuleRow).not.toHaveBeenCalled();
      expect(audit).not.toHaveBeenCalled();
    },
  );
});

describe("deleteSiemRule", () => {
  it("deletes a draft and audits it", async () => {
    repo.findSiemRule.mockResolvedValue(rule());
    repo.deleteSiemRuleRow.mockResolvedValue({ id: ID, name: "x" });
    await deleteSiemRule(admin, "splunk", ID, request, deps());
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "siem_rule.deleted" }),
      request,
    );
  });

  it("refuses to delete a pushed rule (its file lives on GitHub)", async () => {
    repo.findSiemRule.mockResolvedValue(rule({ status: "pushed", github_path: "x" }));
    expect((await failureOf(deleteSiemRule(admin, "splunk", ID, request, deps()))).status).toBe(
      409,
    );
    expect(repo.deleteSiemRuleRow).not.toHaveBeenCalled();
  });
});
