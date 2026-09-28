import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AlertDetail } from "@/lib/alerts/types";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import type { IndicatorDetail } from "@/lib/indicators/types";
import type { InvestigationDetail } from "@/lib/investigations/types";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { AiCompleteRequest, AiProvider } from "@/lib/ai/types";

const repo = vi.hoisted(() => ({
  findAiSettings: vi.fn(),
  updateAiSettings: vi.fn(),
  insertAiAnalysis: vi.fn(),
  findAiAnalyses: vi.fn(),
  updateAlertFalsePositiveScore: vi.fn(),
}));
const integrations = vi.hoisted(() => ({ getIntegrations: vi.fn() }));
const alertsService = vi.hoisted(() => ({ getAlert: vi.fn() }));
const investigationsService = vi.hoisted(() => ({ getInvestigation: vi.fn() }));
const investigationsRepo = vi.hoisted(() => ({ insertChecklistItems: vi.fn() }));
const indicatorsService = vi.hoisted(() => ({ getIndicator: vi.fn() }));
const responseActionsRepo = vi.hoisted(() => ({ seedResponseActionsForAlert: vi.fn() }));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));

vi.mock("@/lib/ai/repository", () => repo);
vi.mock("@/lib/integrations/service", () => integrations);
vi.mock("@/lib/alerts/service", () => alertsService);
vi.mock("@/lib/investigations/service", () => investigationsService);
vi.mock("@/lib/investigations/repository", () => investigationsRepo);
vi.mock("@/lib/indicators/service", () => indicatorsService);
vi.mock("@/lib/response-actions/repository", () => responseActionsRepo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const {
  getAiAvailability,
  setAiAvailability,
  generateAlertAnalysis,
  generateInvestigationAnalysis,
  generateIndicatorAnalysis,
  aiSettingsPatchSchema,
} = await import("@/lib/ai/service");

const request = { headers: new Headers() };
const admin: AuthContext = {
  supabase: {} as AuthClient,
  user: { id: "admin-1", email: "admin@arcradar.test" },
  profile: { display_name: "Admin", role: "admin" },
  permissions: permissionsForRole("admin"),
};

const AI_CATALOG = [
  {
    provider: "groq",
    display_name: "Groq",
    capabilities: ["ai"],
    enabled: true,
    configured: true,
    last_sync_at: null,
  },
  {
    provider: "openai",
    display_name: "OpenAI",
    capabilities: ["ai"],
    enabled: false,
    configured: true,
    last_sync_at: null,
  },
  {
    provider: "ollama",
    display_name: "Ollama (local)",
    capabilities: ["ai"],
    enabled: true,
    configured: false,
    last_sync_at: null,
  },
  {
    provider: "virustotal",
    display_name: "VirusTotal",
    capabilities: ["ip"],
    enabled: true,
    configured: true,
    last_sync_at: null,
  },
];

const ALERT = {
  id: "alert-1",
  title: "fxboard suspicious login",
  description: "Multiple failed logins followed by a success.",
  severity: "high",
  status: "new",
  source: "manual",
  origin: "local",
  created_at: "2026-09-27T00:00:00.000Z",
  indicator: {
    id: "ind-1",
    type: "ipv4",
    value: "203.0.113.9",
    verdict: "suspicious",
    severity: "high",
  },
  asset: { id: "asset-1", name: "WKS-01", ip_address: "10.0.0.5", os: "Windows 10" },
  techniques: [{ id: "T1078", name: "Valid Accounts" }],
  event: {
    id: "event-1",
    title: "Auth failure burst",
    event_type: "auth",
    severity: "high",
    source: "wazuh",
    occurred_at: "2026-09-27T00:00:00.000Z",
    payload: {},
  },
} as unknown as AlertDetail;

const INVESTIGATION = {
  id: "inv-1",
  title: "fxboard Harbor Lights",
  description: "Tracking C2 infrastructure.",
  status: "investigating",
  priority: "high",
  tags: [{ id: "t1", name: "c2", color: null }],
  indicators: [{ id: "ind-1", type: "domain", value: "fx-c2.example", verdict: "malicious" }],
  alerts: [{ id: "alert-1", title: "Beacon", severity: "high", status: "investigating" }],
  notes: [{ kind: "note", body: "Pivoted on the loader check-in URL." }],
} as unknown as InvestigationDetail;

const INDICATOR = {
  id: "ind-1",
  type: "domain",
  value: "fx-c2.example",
  verdict: "suspicious",
  severity: "high",
  status: "active",
  confidence: 50,
  source: "manual",
  description: null,
  tags: [{ id: "t1", name: "c2", color: null }],
  threat_actors: [{ id: "a1", name: "Fxactor Alpha", origin: "local" }],
  campaigns: [],
  malware: [],
} as unknown as IndicatorDetail;

beforeEach(() => {
  vi.clearAllMocks();
  integrations.getIntegrations.mockResolvedValue(AI_CATALOG);
  alertsService.getAlert.mockResolvedValue(ALERT);
  investigationsService.getInvestigation.mockResolvedValue(INVESTIGATION);
  indicatorsService.getIndicator.mockResolvedValue(INDICATOR);
});

describe("getAiAvailability", () => {
  it("is ready only when the active provider is both configured and enabled", async () => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: null,
      updated_at: "2026-09-27T00:00:00.000Z",
    });
    const a = await getAiAvailability(admin.supabase);
    expect(a.ready).toBe(true);
    expect(a.providers.map((p) => p.id).sort()).toEqual(["groq", "ollama", "openai"]);
  });

  it("is not ready when disabled, not configured, or nothing is chosen", async () => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: "openai",
      active_model: null,
      updated_at: null,
    });
    expect((await getAiAvailability(admin.supabase)).ready).toBe(false); // disabled

    repo.findAiSettings.mockResolvedValue({
      active_provider: "ollama",
      active_model: null,
      updated_at: null,
    });
    expect((await getAiAvailability(admin.supabase)).ready).toBe(false); // not configured

    repo.findAiSettings.mockResolvedValue({
      active_provider: null,
      active_model: null,
      updated_at: null,
    });
    expect((await getAiAvailability(admin.supabase)).ready).toBe(false); // none chosen
  });
});

describe("setAiAvailability", () => {
  it("rejects a model without a provider", async () => {
    await expect(
      setAiAvailability(admin, { active_provider: null, active_model: "some-model" }, request),
    ).rejects.toMatchObject({ status: 422 });
    expect(repo.updateAiSettings).not.toHaveBeenCalled();
  });

  it("rejects a provider with no key configured", async () => {
    await expect(
      setAiAvailability(admin, { active_provider: "ollama", active_model: null }, request),
    ).rejects.toMatchObject({ status: 409 });
  });

  it("rejects a provider an administrator disabled", async () => {
    await expect(
      setAiAvailability(admin, { active_provider: "openai", active_model: null }, request),
    ).rejects.toMatchObject({ status: 409 });
  });

  it("accepts a configured, enabled provider and audits without leaking anything sensitive", async () => {
    repo.updateAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: "llama-3.3-70b-versatile",
      updated_at: "2026-09-27T00:00:00.000Z",
    });
    repo.findAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: "llama-3.3-70b-versatile",
      updated_at: "2026-09-27T00:00:00.000Z",
    });
    const result = await setAiAvailability(
      admin,
      { active_provider: "groq", active_model: "llama-3.3-70b-versatile" },
      request,
    );
    expect(result.active_provider).toBe("groq");
    expect(repo.updateAiSettings).toHaveBeenCalledWith(admin.supabase, {
      active_provider: "groq",
      active_model: "llama-3.3-70b-versatile",
      updated_by: "admin-1",
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "ai.settings_updated" }),
      request,
    );
  });

  it("allows clearing the choice entirely", async () => {
    repo.updateAiSettings.mockResolvedValue({
      active_provider: null,
      active_model: null,
      updated_at: null,
    });
    repo.findAiSettings.mockResolvedValue({
      active_provider: null,
      active_model: null,
      updated_at: null,
    });
    await expect(
      setAiAvailability(admin, { active_provider: null, active_model: null }, request),
    ).resolves.toMatchObject({ active_provider: null });
  });

  it("the PATCH schema rejects an unknown provider id", () => {
    expect(
      aiSettingsPatchSchema.safeParse({ active_provider: "made-up", active_model: null }).success,
    ).toBe(false);
  });
});

function fakeProvider(complete: AiProvider["complete"]): AiProvider {
  return { info: { id: "groq", name: "Groq" }, complete };
}

describe("generateAlertAnalysis", () => {
  beforeEach(() => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: "custom-model",
      updated_at: null,
    });
  });

  it("503s when no provider is active and ready", async () => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: null,
      active_model: null,
      updated_at: null,
    });
    await expect(
      generateAlertAnalysis(admin, "alert-1", "threat_summary", request, {
        registry: new Map(),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 503 });
    expect(repo.insertAiAnalysis).not.toHaveBeenCalled();
  });

  it("503s when the active provider drifted out of the registry", async () => {
    await expect(
      generateAlertAnalysis(admin, "alert-1", "threat_summary", request, {
        registry: new Map(),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 503 });
  });

  it("builds the prompt from the alert, validates the answer, stores and audits it", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: {
        summary: "A suspicious login was observed.",
        key_points: ["Multiple failed attempts"],
      },
      model: "custom-model",
      usage: { input: 100, output: 40 },
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-1",
      kind: "threat_summary",
      subject_type: "alert",
      subject_id: "alert-1",
      provider: "groq",
      model: "custom-model",
      prompt_version: 1,
      content: {
        summary: "A suspicious login was observed.",
        key_points: ["Multiple failed attempts"],
      },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });

    const row = await generateAlertAnalysis(admin, "alert-1", "threat_summary", request, {
      registry: new Map([["groq", fakeProvider(complete)]]),
      timeoutMs: 50,
      audit,
    });

    expect(row.id).toBe("row-1");
    const callArg = complete.mock.calls[0][0] as AiCompleteRequest;
    expect(callArg.model).toBe("custom-model");
    expect(callArg.user).toContain("fxboard suspicious login");
    expect(callArg.user).toContain("203.0.113.9");
    expect(repo.insertAiAnalysis).toHaveBeenCalledWith(
      admin.supabase,
      expect.objectContaining({
        kind: "threat_summary",
        subject_type: "alert",
        subject_id: "alert-1",
      }),
    );
    expect(repo.updateAlertFalsePositiveScore).not.toHaveBeenCalled();
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "ai.analysis_generated" }),
      request,
    );
  });

  it("caches the score on the alert for false_positive_score", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: { score: 82, reasoning: "Matches a known benign pattern." },
      model: "custom-model",
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-2",
      kind: "false_positive_score",
      subject_type: "alert",
      subject_id: "alert-1",
      provider: "groq",
      model: "custom-model",
      prompt_version: 1,
      content: { score: 82, reasoning: "Matches a known benign pattern." },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });

    await generateAlertAnalysis(admin, "alert-1", "false_positive_score", request, {
      registry: new Map([["groq", fakeProvider(complete)]]),
      timeoutMs: 50,
      audit,
    });

    expect(repo.updateAlertFalsePositiveScore).toHaveBeenCalledWith(admin.supabase, "alert-1", 82);
  });

  it("does not fail the request when caching the score fails", async () => {
    const complete = vi
      .fn()
      .mockResolvedValue({ data: { score: 10, reasoning: "Looks real." }, model: "m" });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-3",
      kind: "false_positive_score",
      subject_type: "alert",
      subject_id: "alert-1",
      provider: "groq",
      model: "m",
      prompt_version: 1,
      content: { score: 10, reasoning: "Looks real." },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });
    repo.updateAlertFalsePositiveScore.mockRejectedValue(new Error("RLS blocked it"));

    await expect(
      generateAlertAnalysis(admin, "alert-1", "false_positive_score", request, {
        registry: new Map([["groq", fakeProvider(complete)]]),
        timeoutMs: 50,
        audit,
      }),
    ).resolves.toMatchObject({ id: "row-3" });
  });

  it("maps a rate-limited provider to 429 and never stores a row", async () => {
    const { AiProviderError } = await import("@/lib/ai/types");
    const complete = vi
      .fn()
      .mockRejectedValue(new AiProviderError("rate_limited", "slow down", 12));
    await expect(
      generateAlertAnalysis(admin, "alert-1", "threat_summary", request, {
        registry: new Map([["groq", fakeProvider(complete)]]),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 429 });
    expect(repo.insertAiAnalysis).not.toHaveBeenCalled();
  });

  it("503s and stores nothing when the provider's answer fails schema validation", async () => {
    const complete = vi.fn().mockResolvedValue({ data: { unexpected: true }, model: "m" });
    await expect(
      generateAlertAnalysis(admin, "alert-1", "threat_summary", request, {
        registry: new Map([["groq", fakeProvider(complete)]]),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 503 });
    expect(repo.insertAiAnalysis).not.toHaveBeenCalled();
  });

  it("seeds a catalog entry and a recommended log row per suggested response action", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: { actions: [{ title: "Isolate the host", why: "Stop the beacon.", urgency: "high" }] },
      model: "custom-model",
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-4",
      kind: "response_actions",
      subject_type: "alert",
      subject_id: "alert-1",
      provider: "groq",
      model: "custom-model",
      prompt_version: 1,
      content: {
        actions: [{ title: "Isolate the host", why: "Stop the beacon.", urgency: "high" }],
      },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });

    await generateAlertAnalysis(admin, "alert-1", "response_actions", request, {
      registry: new Map([["groq", fakeProvider(complete)]]),
      timeoutMs: 50,
      audit,
    });

    expect(responseActionsRepo.seedResponseActionsForAlert).toHaveBeenCalledWith(
      admin.supabase,
      "alert-1",
      [{ title: "Isolate the host", why: "Stop the beacon.", urgency: "high" }],
    );
  });

  it("does not fail the request when seeding response actions fails", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: { actions: [{ title: "Isolate the host", why: "Stop it.", urgency: "high" }] },
      model: "m",
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-5",
      kind: "response_actions",
      subject_type: "alert",
      subject_id: "alert-1",
      provider: "groq",
      model: "m",
      prompt_version: 1,
      content: { actions: [{ title: "Isolate the host", why: "Stop it.", urgency: "high" }] },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });
    responseActionsRepo.seedResponseActionsForAlert.mockRejectedValue(new Error("RLS blocked it"));

    await expect(
      generateAlertAnalysis(admin, "alert-1", "response_actions", request, {
        registry: new Map([["groq", fakeProvider(complete)]]),
        timeoutMs: 50,
        audit,
      }),
    ).resolves.toMatchObject({ id: "row-5" });
  });

  it("422s a kind that does not belong to an alert", async () => {
    await expect(
      generateAlertAnalysis(admin, "alert-1", "investigation_checklist", request, {
        registry: new Map([["groq", fakeProvider(vi.fn())]]),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 422 });
    expect(repo.insertAiAnalysis).not.toHaveBeenCalled();
  });
});

describe("generateInvestigationAnalysis", () => {
  beforeEach(() => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: null,
      updated_at: null,
    });
  });

  it("builds the prompt from the investigation and seeds trackable checklist items", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: { items: ["Pull DNS logs for the affected host", "Check for lateral movement"] },
      model: "m",
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-6",
      kind: "investigation_checklist",
      subject_type: "investigation",
      subject_id: "inv-1",
      provider: "groq",
      model: "m",
      prompt_version: 1,
      content: { items: ["Pull DNS logs for the affected host", "Check for lateral movement"] },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });

    const row = await generateInvestigationAnalysis(
      admin,
      "inv-1",
      "investigation_checklist",
      request,
      { registry: new Map([["groq", fakeProvider(complete)]]), timeoutMs: 50, audit },
    );

    expect(row.id).toBe("row-6");
    const callArg = complete.mock.calls[0][0] as AiCompleteRequest;
    expect(callArg.user).toContain("fxboard Harbor Lights");
    expect(callArg.user).toContain("fx-c2.example");
    expect(investigationsRepo.insertChecklistItems).toHaveBeenCalledWith(admin.supabase, "inv-1", [
      "Pull DNS logs for the affected host",
      "Check for lateral movement",
    ]);
  });

  it("422s a kind that does not belong to an investigation", async () => {
    await expect(
      generateInvestigationAnalysis(admin, "inv-1", "threat_summary", request, {
        registry: new Map([["groq", fakeProvider(vi.fn())]]),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 422 });
  });
});

describe("generateIndicatorAnalysis", () => {
  beforeEach(() => {
    repo.findAiSettings.mockResolvedValue({
      active_provider: "groq",
      active_model: null,
      updated_at: null,
    });
  });

  it("builds the prompt from the indicator and has no side effect (applying is a normal edit)", async () => {
    const complete = vi.fn().mockResolvedValue({
      data: { verdict: "malicious", confidence: 80, reasoning: "Linked to a known C2 actor." },
      model: "m",
    });
    repo.insertAiAnalysis.mockResolvedValue({
      id: "row-7",
      kind: "verdict_recommendation",
      subject_type: "indicator",
      subject_id: "ind-1",
      provider: "groq",
      model: "m",
      prompt_version: 1,
      content: { verdict: "malicious", confidence: 80, reasoning: "Linked to a known C2 actor." },
      requested_by: "admin-1",
      created_at: "2026-09-27T00:00:00.000Z",
    });

    const row = await generateIndicatorAnalysis(admin, "ind-1", "verdict_recommendation", request, {
      registry: new Map([["groq", fakeProvider(complete)]]),
      timeoutMs: 50,
      audit,
    });

    expect(row.id).toBe("row-7");
    const callArg = complete.mock.calls[0][0] as AiCompleteRequest;
    expect(callArg.user).toContain("fx-c2.example");
    expect(callArg.user).toContain("Fxactor Alpha");
    expect(investigationsRepo.insertChecklistItems).not.toHaveBeenCalled();
    expect(responseActionsRepo.seedResponseActionsForAlert).not.toHaveBeenCalled();
  });

  it("422s a kind that does not belong to an indicator", async () => {
    await expect(
      generateIndicatorAnalysis(admin, "ind-1", "false_positive_score", request, {
        registry: new Map([["groq", fakeProvider(vi.fn())]]),
        timeoutMs: 50,
        audit,
      }),
    ).rejects.toMatchObject({ status: 422 });
  });
});
