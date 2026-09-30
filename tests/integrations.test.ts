import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import type { ServerEnv } from "@/lib/env/server";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  findIntegrationRows: vi.fn(),
  findDisabledProviders: vi.fn(),
  updateIntegrationEnabled: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));
const ENV = vi.hoisted((): ServerEnv => ({
  SUPABASE_SERVICE_ROLE_KEY: "x",
  VIRUSTOTAL_API_KEY: "vt-key",
  ABUSEIPDB_API_KEY: undefined,
  OTX_API_KEY: undefined,
  SHODAN_INTERNETDB: undefined,
  NVD_API_KEY: undefined,
  GROQ_API_KEY: "groq-key",
  OPENAI_API_KEY: undefined,
  ANTHROPIC_API_KEY: undefined,
  DEEPSEEK_API_KEY: undefined,
  OLLAMA_BASE_URL: undefined,
}));
vi.mock("@/lib/integrations/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/env/server", () => ({ getServerEnv: () => ENV }));

const { getIntegrations, setIntegrationEnabled } = await import("@/lib/integrations/service");

const request = { headers: new Headers() };
const admin: AuthContext = {
  supabase: {} as AuthClient,
  user: { id: "admin-1", email: "admin@arcradar.test" },
  profile: { display_name: "Admin", role: "admin" },
  permissions: permissionsForRole("admin"),
};

beforeEach(() => vi.clearAllMocks());

describe("getIntegrations", () => {
  it("marks a provider configured only when its key is set, and demo/wazuh always", async () => {
    repo.findIntegrationRows.mockResolvedValue([
      {
        provider: "demo",
        display_name: "Demo",
        capabilities: [],
        enabled: true,
        last_sync_at: null,
      },
      {
        provider: "virustotal",
        display_name: "VirusTotal",
        capabilities: ["ip"],
        enabled: true,
        last_sync_at: null,
      },
      {
        provider: "abuseipdb",
        display_name: "AbuseIPDB",
        capabilities: ["ip"],
        enabled: true,
        last_sync_at: null,
      },
      {
        provider: "wazuh",
        display_name: "Wazuh",
        capabilities: ["telemetry"],
        enabled: false,
        last_sync_at: "2026-09-27T00:00:00Z",
      },
      {
        provider: "groq",
        display_name: "Groq",
        capabilities: ["ai"],
        enabled: true,
        last_sync_at: null,
      },
      {
        provider: "ollama",
        display_name: "Ollama (local)",
        capabilities: ["ai"],
        enabled: true,
        last_sync_at: null,
      },
    ]);

    const rows = await getIntegrations({} as AuthClient, ENV);
    const byProvider = Object.fromEntries(rows.map((r) => [r.provider, r]));
    expect(byProvider.demo.configured).toBe(true);
    expect(byProvider.virustotal.configured).toBe(true);
    expect(byProvider.abuseipdb.configured).toBe(false);
    expect(byProvider.wazuh.configured).toBe(true);
    expect(byProvider.wazuh.enabled).toBe(false);
    // AI providers are configured the same way as any other: a server-side key (or, for Ollama, its
    // base URL) present in the environment.
    expect(byProvider.groq.configured).toBe(true);
    expect(byProvider.ollama.configured).toBe(false);
  });
});

describe("setIntegrationEnabled", () => {
  it("404s an unknown provider without writing anything", async () => {
    await expect(
      setIntegrationEnabled(admin, "not-a-real-provider", false, request),
    ).rejects.toMatchObject({ status: 404 });
    expect(repo.updateIntegrationEnabled).not.toHaveBeenCalled();
  });

  it("refuses to turn the demo provider off", async () => {
    await expect(setIntegrationEnabled(admin, "demo", false, request)).rejects.toMatchObject({
      status: 409,
    });
    expect(repo.updateIntegrationEnabled).not.toHaveBeenCalled();
  });

  it("turning demo on (a no-op) is not refused", async () => {
    repo.updateIntegrationEnabled.mockResolvedValue({
      provider: "demo",
      display_name: "Demo",
      capabilities: [],
      enabled: true,
      last_sync_at: null,
    });
    await expect(setIntegrationEnabled(admin, "demo", true, request)).resolves.toBeDefined();
  });

  it("404s when the provider row does not exist even though the name is known", async () => {
    repo.updateIntegrationEnabled.mockResolvedValue(null);
    await expect(setIntegrationEnabled(admin, "virustotal", false, request)).rejects.toMatchObject({
      status: 404,
    });
  });

  it("writes the change and audits it, without the key's value anywhere", async () => {
    repo.updateIntegrationEnabled.mockResolvedValue({
      provider: "virustotal",
      display_name: "VirusTotal",
      capabilities: ["ip"],
      enabled: false,
      last_sync_at: null,
    });
    const row = await setIntegrationEnabled(admin, "virustotal", false, request);
    expect(row.enabled).toBe(false);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "integration.updated",
        entityId: "virustotal",
        metadata: { enabled: false },
      }),
      request,
    );
    expect(JSON.stringify(audit.mock.calls[0][0])).not.toMatch(/vt-key|API_KEY/);
  });
});
