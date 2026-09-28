import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { ProviderError } from "@/lib/intel/types";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type {
  VulnerabilityDetail,
  VulnerabilityProvider,
  VulnerabilityRecord,
} from "@/lib/vulnerabilities/types";

const repo = vi.hoisted(() => ({
  findVulnerabilities: vi.fn(),
  findVulnerabilityDetail: vi.fn(),
  findSeverityStats: vi.fn(),
  findVulnerabilityOrigin: vi.fn(),
  importExternalVulnerability: vi.fn(),
}));
vi.mock("@/lib/vulnerabilities/repository", () => repo);

const { getVulnerability, getVulnerabilityProvider, importVulnerability, listVulnerabilities } =
  await import("@/lib/vulnerabilities/service");

const NOW = new Date("2026-09-26T12:00:00.000Z");
const auth = (role: "admin" | "analyst" | "viewer" = "admin"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: "admin@arcradar.test" },
  profile: { display_name: role, role },
  permissions: permissionsForRole(role),
});
const request = { headers: new Headers() };

const RECORD: VulnerabilityRecord = {
  cve_id: "CVE-2099-0001",
  title: "Fixture vulnerability",
  description: "Described.",
  cvss_score: 9.8,
  cvss_vector: "CVSS:3.1/AV:N",
  cvss_version: "3.1",
  severity: "critical",
  exploit_status: "unknown",
  remediation: null,
  reference_urls: [],
  published_at: null,
  modified_at: null,
  affected_products: [],
};
const DETAIL = {
  cve_id: "CVE-2099-0001",
  affected_products: [],
  indicator: null,
} as unknown as VulnerabilityDetail;

const nvd = (lookupCve: VulnerabilityProvider["lookupCve"]): VulnerabilityProvider => ({
  info: { id: "nvd", name: "NVD", origin: "external" },
  lookupCve,
});

function deps(provider: VulnerabilityProvider | null) {
  const audit = vi.fn().mockResolvedValue(true);
  return {
    audit,
    store: repo.importExternalVulnerability,
    value: {
      provider,
      now: () => NOW,
      timeoutMs: 100,
      audit,
      store: repo.importExternalVulnerability,
    },
  };
}

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
  repo.findVulnerabilityOrigin.mockResolvedValue(null);
  repo.findVulnerabilityDetail.mockResolvedValue(DETAIL);
  repo.importExternalVulnerability.mockResolvedValue(undefined);
});

describe("importVulnerability", () => {
  it("fetches the CVE, stores it as external data, audits it and returns the stored record", async () => {
    const lookupCve = vi.fn().mockResolvedValue(RECORD);
    const { value, audit } = deps(nvd(lookupCve));
    const result = await importVulnerability(auth(), "cve-2099-0001", request, value);

    expect(lookupCve).toHaveBeenCalledWith("CVE-2099-0001", {
      signal: expect.any(AbortSignal),
      now: NOW,
    });
    expect(repo.importExternalVulnerability).toHaveBeenCalledWith(RECORD);
    expect(audit).toHaveBeenCalledWith(
      {
        action: "vulnerability.imported",
        userId: "user-1",
        entityType: "vulnerability",
        entityId: "CVE-2099-0001",
        metadata: { provider: "nvd", refreshed: false },
      },
      request,
    );
    expect(result).toEqual({ vulnerability: DETAIL, created: true });
  });

  it("refreshes a record that is already external and says so", async () => {
    repo.findVulnerabilityOrigin.mockResolvedValue("external");
    const { value, audit } = deps(nvd(vi.fn().mockResolvedValue(RECORD)));
    const result = await importVulnerability(auth(), "CVE-2099-0001", request, value);

    expect(result.created).toBe(false);
    expect(audit.mock.calls[0][0].metadata).toEqual({ provider: "nvd", refreshed: true });
  });

  it.each(["demo", "local"] as const)(
    "never replaces a %s record (409) and does not even ask the provider",
    async (origin) => {
      repo.findVulnerabilityOrigin.mockResolvedValue(origin);
      const lookupCve = vi.fn();
      const { value, audit } = deps(nvd(lookupCve));
      const error = await failureOf(importVulnerability(auth(), "CVE-2099-0001", request, value));

      expect(error).toMatchObject({ status: 409, code: "CONFLICT" });
      expect(lookupCve).not.toHaveBeenCalled();
      expect(repo.importExternalVulnerability).not.toHaveBeenCalled();
      expect(audit).not.toHaveBeenCalled();
    },
  );

  it("is 503 when no provider is connected, and stores nothing", async () => {
    const { value, audit } = deps(null);
    const error = await failureOf(importVulnerability(auth(), "CVE-2099-0001", request, value));
    expect(error).toMatchObject({ status: 503, code: "DEPENDENCY_UNAVAILABLE" });
    expect(error.message).toMatch(/NVD/);
    expect(repo.importExternalVulnerability).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("is 404 when the provider has no such CVE", async () => {
    const { value } = deps(nvd(vi.fn().mockResolvedValue(null)));
    const error = await failureOf(importVulnerability(auth(), "CVE-2099-0001", request, value));
    expect(error).toMatchObject({ status: 404 });
    expect(error.message).toContain("CVE-2099-0001");
    expect(repo.importExternalVulnerability).not.toHaveBeenCalled();
  });

  it("maps a provider's rate limit to 429 with Retry-After, other failures to 503", async () => {
    const limited = await failureOf(
      importVulnerability(
        auth(),
        "CVE-2099-0001",
        request,
        deps(nvd(vi.fn().mockRejectedValue(new ProviderError("rate_limited", "slow down", 30))))
          .value,
      ),
    );
    expect(limited).toMatchObject({
      status: 429,
      code: "RATE_LIMITED",
      headers: { "Retry-After": "30" },
    });

    const rejected = await failureOf(
      importVulnerability(
        auth(),
        "CVE-2099-0001",
        request,
        deps(
          nvd(
            vi
              .fn()
              .mockRejectedValue(new ProviderError("auth", "The provider rejected the API key.")),
          ),
        ).value,
      ),
    );
    expect(rejected).toMatchObject({ status: 503 });
    expect(rejected.message).toBe("NVD: The provider rejected the API key.");
    expect(repo.importExternalVulnerability).not.toHaveBeenCalled();
  });

  it("does not leak an unexpected error", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const error = await failureOf(
      importVulnerability(
        auth(),
        "CVE-2099-0001",
        request,
        deps(nvd(vi.fn().mockRejectedValue(new Error("internal secret detail")))).value,
      ),
    );
    spy.mockRestore();
    expect(error.status).toBe(503);
    expect(error.message).not.toContain("secret");
  });

  it("rejects a malformed id before doing anything", async () => {
    const lookupCve = vi.fn();
    const error = await failureOf(
      importVulnerability(auth(), "not-a-cve", request, deps(nvd(lookupCve)).value),
    );
    expect(error).toMatchObject({ status: 422 });
    expect(lookupCve).not.toHaveBeenCalled();
    expect(repo.findVulnerabilityOrigin).not.toHaveBeenCalled();
  });
});

describe("reading vulnerabilities", () => {
  it("normalizes and validates the id, and answers 404 for a missing record", async () => {
    expect(await getVulnerability({} as AuthClient, "cve-2099-0001")).toBe(DETAIL);
    expect(repo.findVulnerabilityDetail).toHaveBeenCalledWith({}, "CVE-2099-0001");

    expect(await failureOf(getVulnerability({} as AuthClient, "nonsense"))).toMatchObject({
      status: 404,
    });
    expect(repo.findVulnerabilityDetail).toHaveBeenCalledTimes(1);

    repo.findVulnerabilityDetail.mockResolvedValue(null);
    expect(await failureOf(getVulnerability({} as AuthClient, "CVE-2099-0002"))).toMatchObject({
      status: 404,
    });
  });

  it("wraps a list in the standard page shape", async () => {
    repo.findVulnerabilities.mockResolvedValue({ rows: [{ id: "1" }, { id: "2" }], total: 51 });
    const page = await listVulnerabilities({} as AuthClient, {
      page: 2,
      page_size: 25,
      sort: "published_at",
      order: "desc",
    });
    expect(page).toEqual({
      items: [{ id: "1" }, { id: "2" }],
      pagination: { page: 2, page_size: 25, total: 51, total_pages: 3 },
    });
  });
});

describe("getVulnerabilityProvider", () => {
  it("connects NVD only when its key is set", () => {
    expect(getVulnerabilityProvider({ NVD_API_KEY: undefined })).toBeNull();
    expect(getVulnerabilityProvider({ NVD_API_KEY: "key" })?.info).toEqual({
      id: "nvd",
      name: "NVD",
      origin: "external",
    });
  });
});
