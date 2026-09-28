import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";
import type { ActorDetail } from "@/lib/threat-intel/types";
import type { InvestigationDetail } from "@/lib/investigations/types";
import type { VulnerabilityStats } from "@/lib/vulnerabilities/types";

const repo = vi.hoisted(() => ({
  findReports: vi.fn(),
  findReport: vi.fn(),
  insertReport: vi.fn(),
  deleteReportRow: vi.fn(),
}));
const investigations = vi.hoisted(() => ({ getInvestigation: vi.fn() }));
const threatIntel = vi.hoisted(() => ({ getActor: vi.fn() }));
const indicators = vi.hoisted(() => ({ listIndicators: vi.fn() }));
const alerts = vi.hoisted(() => ({ listAlerts: vi.fn(), getAlertStats: vi.fn() }));
const vulnerabilities = vi.hoisted(() => ({
  listVulnerabilities: vi.fn(),
  getVulnerabilityStats: vi.fn(),
}));
const dashboardRepo = vi.hoisted(() => ({
  findIndicatorTypeCounts: vi.fn(),
  findIndicatorVerdictCounts: vi.fn(),
  findAlertSeverityCounts: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));
const team = vi.hoisted(() => ({ findDisplayNames: vi.fn().mockResolvedValue(new Map()) }));

vi.mock("@/lib/reports/repository", () => repo);
vi.mock("@/lib/investigations/service", () => investigations);
vi.mock("@/lib/threat-intel/service", () => threatIntel);
vi.mock("@/lib/indicators/service", () => indicators);
vi.mock("@/lib/alerts/service", () => alerts);
vi.mock("@/lib/vulnerabilities/service", () => vulnerabilities);
vi.mock("@/lib/dashboard/repository", () => dashboardRepo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/team/repository", () => team);

const { createReport, deleteReport, getReport, isReportId, listReports } =
  await import("@/lib/reports/service");
const { createReportSchema } = await import("@/lib/reports/schema");

const request = { headers: new Headers() };
const auth = (role: "admin" | "analyst" | "viewer" = "analyst"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: "user-1", email: "analyst@arcradar.test" },
  profile: { display_name: "Fixture Analyst", role },
  permissions: permissionsForRole(role),
});

beforeEach(() => {
  vi.clearAllMocks();
  repo.insertReport.mockImplementation(async (_supabase, row) => ({
    id: "report-1",
    title: row.title,
    type: row.type,
    investigation_id: row.investigation_id,
    parameters: row.parameters,
    content: row.content,
    origin: "local",
    created_by: "user-1",
    created_at: "2026-09-27T00:00:00.000Z",
  }));
});

describe("createReportSchema", () => {
  it("requires the field each type needs, and nothing else", () => {
    expect(createReportSchema.safeParse({ type: "investigation" }).success).toBe(false);
    expect(
      createReportSchema.safeParse({
        type: "investigation",
        investigation_id: "11111111-1111-4111-8111-111111111111",
      }).success,
    ).toBe(true);
    expect(createReportSchema.safeParse({ type: "threat_actor" }).success).toBe(false);
    expect(createReportSchema.safeParse({ type: "vulnerabilities" }).success).toBe(true);
    // A field belonging to a different type is rejected (strict per-branch objects).
    expect(
      createReportSchema.safeParse({ type: "vulnerabilities", investigation_id: "x" }).success,
    ).toBe(false);
  });

  it("title is optional but bounded when given", () => {
    expect(createReportSchema.safeParse({ type: "vulnerabilities", title: "" }).success).toBe(
      false,
    );
    expect(
      createReportSchema.safeParse({ type: "vulnerabilities", title: "x".repeat(301) }).success,
    ).toBe(false);
  });
});

describe("createReport", () => {
  it("builds an investigation report from the investigation's own detail", async () => {
    const detail: InvestigationDetail = {
      id: "inv-1",
      title: "Fxreport Case",
      status: "investigating",
      priority: "high",
      created_at: "2026-09-01T00:00:00Z",
      updated_at: "2026-09-02T00:00:00Z",
      analyst: { id: "user-2", display_name: "Someone" },
      indicators: [
        {
          id: "ind-1",
          type: "ipv4",
          value: "203.0.113.10",
          verdict: "malicious",
          severity: "high",
          origin: "local",
          added_at: "",
          added_by_name: null,
        },
      ],
      alerts: [],
      notes: [
        {
          id: "n1",
          kind: "note",
          body: "Fxreport note body",
          author_id: "user-2",
          author_name: "Someone",
          created_at: "2026-09-02T00:00:00Z",
          updated_at: "2026-09-02T00:00:00Z",
        },
      ],
      evidence: [],
      timeline: [],
    } as unknown as InvestigationDetail;
    investigations.getInvestigation.mockResolvedValue(detail);

    const report = await createReport(
      auth(),
      { type: "investigation", investigation_id: "11111111-1111-4111-8111-111111111111" },
      request,
    );

    expect(investigations.getInvestigation).toHaveBeenCalledWith(
      expect.anything(),
      "11111111-1111-4111-8111-111111111111",
    );
    expect(report.title).toBe("Investigation report: Fxreport Case");
    expect(report.content).toMatchObject({
      investigation: expect.objectContaining({ title: "Fxreport Case", analyst: "Someone" }),
      indicators: [{ id: "ind-1", type: "ipv4", value: "203.0.113.10" }],
      notes: [expect.objectContaining({ body: "Fxreport note body" })],
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "report.created", entityId: "report-1" }),
      request,
    );
  });

  it("builds a threat actor report from the actor's linked records", async () => {
    const actor: ActorDetail = {
      id: "actor-1",
      name: "Fxreport Actor",
      description: "desc",
      motivation: "financial",
      campaigns: [{ id: "c1", name: "Camp", status: "active", origin: "local", last_seen: null }],
      malware: [{ id: "m1", name: "Mal", malware_type: null, origin: "local" }],
      techniques: [{ id: "T1110", name: "Brute Force", tactics: [] }],
      indicators: { items: [], total: 7 },
    } as unknown as ActorDetail;
    threatIntel.getActor.mockResolvedValue(actor);

    const report = await createReport(
      auth("admin"),
      { type: "threat_actor", threat_actor_id: "22222222-2222-4222-8222-222222222222" },
      request,
    );

    expect(report.title).toBe("Threat actor activity: Fxreport Actor");
    expect(report.content).toMatchObject({
      actor: { id: "actor-1", name: "Fxreport Actor" },
      indicator_count: 7,
      campaigns: [{ id: "c1", name: "Camp", status: "active" }],
    });
  });

  it("builds a vulnerability summary from severity stats and the exploited list", async () => {
    const stats: VulnerabilityStats = {
      total: 12,
      exploited: 2,
      by_severity: [{ severity: "critical", total: 3, exploited: 2 }],
    };
    vulnerabilities.getVulnerabilityStats.mockResolvedValue(stats);
    vulnerabilities.listVulnerabilities.mockResolvedValue({
      items: [{ cve_id: "CVE-2021-44228", title: "Log4Shell", cvss_score: 10 }],
      pagination: { page: 1, page_size: 10, total: 1, total_pages: 1 },
    });

    const report = await createReport(auth("admin"), { type: "vulnerabilities" }, request);

    expect(vulnerabilities.listVulnerabilities).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ exploit_status: "exploited_in_wild" }),
    );
    expect(report.content).toMatchObject({
      total: 12,
      exploited_in_wild: [{ cve_id: "CVE-2021-44228", title: "Log4Shell", cvss_score: 10 }],
    });
    expect(report.title).toMatch(/^Vulnerability summary — \d{4}-\d{2}-\d{2}$/);
  });

  it("an explicit title overrides the generated default", async () => {
    vulnerabilities.getVulnerabilityStats.mockResolvedValue({
      total: 0,
      exploited: 0,
      by_severity: [],
    });
    vulnerabilities.listVulnerabilities.mockResolvedValue({
      items: [],
      pagination: { page: 1, page_size: 10, total: 0, total_pages: 0 },
    });
    const report = await createReport(
      auth("admin"),
      { type: "vulnerabilities", title: "My own title" },
      request,
    );
    expect(report.title).toBe("My own title");
  });
});

describe("listReports / getReport / deleteReport", () => {
  it("lists reports with the creator's display name resolved", async () => {
    repo.findReports.mockResolvedValue({
      rows: [
        {
          id: "r1",
          title: "T",
          type: "alerts",
          investigation_id: null,
          origin: "local",
          created_by: "user-2",
          created_at: "2026-09-27T00:00:00Z",
          parameters: {},
          content: {},
        },
      ],
      total: 1,
    });
    team.findDisplayNames.mockResolvedValue(new Map([["user-2", "Someone"]]));

    const page = await listReports(auth("viewer"), { page: 1, page_size: 25 });
    expect(page.items[0]).toMatchObject({ id: "r1", created_by_name: "Someone" });
  });

  it("getReport 404s for an unknown or malformed id", async () => {
    expect(isReportId("not-a-uuid")).toBe(false);
    repo.findReport.mockResolvedValue(null);
    await expect(
      getReport(auth("viewer"), "33333333-3333-4333-8333-333333333333"),
    ).rejects.toMatchObject({
      status: 404,
    });
  });

  it("deleteReport audits the removal and 404s if nothing was removed", async () => {
    repo.findReport.mockResolvedValue({
      id: "r1",
      title: "T",
      type: "alerts",
      created_by: "user-1",
    });
    repo.deleteReportRow.mockResolvedValue(true);
    await deleteReport(auth("admin"), "33333333-3333-4333-8333-333333333333", request);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "report.deleted" }),
      request,
    );

    repo.deleteReportRow.mockResolvedValue(false);
    await expect(
      deleteReport(auth("admin"), "33333333-3333-4333-8333-333333333333", request),
    ).rejects.toMatchObject({ status: 404 });
  });
});
