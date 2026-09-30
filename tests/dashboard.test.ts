import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  findCounts: vi.fn(),
  findAlertSeverityCounts: vi.fn(),
  findIndicatorTypeCounts: vi.fn(),
  findIndicatorVerdictCounts: vi.fn(),
  findActivity: vi.fn(),
}));
const mitre = vi.hoisted(() => ({ getTopTechniques: vi.fn() }));
const indicators = vi.hoisted(() => ({ listIndicators: vi.fn() }));
const alerts = vi.hoisted(() => ({ listAlerts: vi.fn() }));
const investigations = vi.hoisted(() => ({ listInvestigations: vi.fn() }));

vi.mock("@/lib/dashboard/repository", () => repo);
vi.mock("@/lib/mitre/service", () => mitre);
vi.mock("@/lib/indicators/service", () => indicators);
vi.mock("@/lib/alerts/service", () => alerts);
vi.mock("@/lib/investigations/service", () => investigations);

const { getDashboardData } = await import("@/lib/dashboard/service");
const { dashboardQuerySchema } = await import("@/lib/dashboard/schema");

const auth: AuthContext = {
  supabase: {} as AuthClient,
  user: { id: "user-1", email: "viewer@arcradar.test" },
  profile: { display_name: "Viewer", role: "viewer" },
  permissions: permissionsForRole("viewer"),
};

const page = (items: unknown[]) => ({
  items,
  pagination: { page: 1, page_size: 25, total: items.length, total_pages: 1 },
});

beforeEach(() => {
  vi.clearAllMocks();
  repo.findCounts.mockResolvedValue({
    indicators_total: 1,
    indicators_malicious: 1,
    indicators_suspicious: 0,
    alerts_active: 1,
    vulnerabilities_critical: 1,
    investigations_open: 1,
    events_recent: 1,
    alerts_recent: 1,
  });
  repo.findAlertSeverityCounts.mockResolvedValue([{ severity: "high", total: 1 }]);
  repo.findIndicatorTypeCounts.mockResolvedValue([{ type: "ipv4", total: 1 }]);
  repo.findIndicatorVerdictCounts.mockResolvedValue([{ verdict: "malicious", total: 1 }]);
  repo.findActivity.mockResolvedValue([{ day: "2026-09-27", alerts: 1, events: 1 }]);
  mitre.getTopTechniques.mockResolvedValue([
    { id: "T1110", name: "Brute Force", alert_count: 2, max_severity: "high" },
  ]);
  indicators.listIndicators
    .mockResolvedValueOnce(page([{ id: "malicious-1" }])) // top malicious
    .mockResolvedValueOnce(page([{ id: "recent-1" }])); // recent indicators
  alerts.listAlerts.mockResolvedValue(page([{ id: "alert-1" }]));
  investigations.listInvestigations.mockResolvedValue(page([{ id: "inv-1" }]));
});

describe("dashboardQuerySchema", () => {
  it("defaults to 14 days and clamps to 1-90", () => {
    expect(dashboardQuerySchema.parse({}).days).toBe(14);
    expect(dashboardQuerySchema.safeParse({ days: "0" }).success).toBe(false);
    expect(dashboardQuerySchema.safeParse({ days: "91" }).success).toBe(false);
    expect(dashboardQuerySchema.parse({ severity: "" }).severity).toBeUndefined();
  });
});

describe("getDashboardData", () => {
  it("puts every result in its own field, not shifted by one (each mock is distinct on purpose)", async () => {
    const data = await getDashboardData(auth, { days: 14, severity: undefined });

    expect(data.counts.indicators_total).toBe(1);
    expect(data.severity_distribution).toEqual([{ severity: "high", total: 1 }]);
    expect(data.ioc_distribution).toEqual([{ type: "ipv4", total: 1 }]);
    expect(data.verdict_distribution).toEqual([{ verdict: "malicious", total: 1 }]);
    expect(data.activity).toEqual([{ day: "2026-09-27", alerts: 1, events: 1 }]);
    expect(data.top_techniques).toEqual([
      { id: "T1110", name: "Brute Force", alert_count: 2, max_severity: "high" },
    ]);
    expect(data.top_malicious_indicators).toEqual([{ id: "malicious-1" }]);
    expect(data.recent_indicators).toEqual([{ id: "recent-1" }]);
    expect(data.recent_alerts).toEqual([{ id: "alert-1" }]);
    expect(data.recent_investigations).toEqual([{ id: "inv-1" }]);
  });

  it("threads the selected days into the activity window and severity into alerts and indicators", async () => {
    await getDashboardData(auth, { days: 30, severity: "critical" });

    expect(repo.findCounts).toHaveBeenCalledWith(auth.supabase, 30);
    expect(repo.findActivity).toHaveBeenCalledWith(auth.supabase, 30);
    expect(alerts.listAlerts).toHaveBeenCalledWith(
      auth,
      expect.objectContaining({ severity: "critical" }),
    );
    expect(indicators.listIndicators).toHaveBeenCalledWith(
      auth.supabase,
      expect.objectContaining({ severity: "critical", verdict: "malicious" }),
    );
    expect(indicators.listIndicators).toHaveBeenCalledWith(
      auth.supabase,
      expect.objectContaining({ severity: "critical" }),
    );
  });
});
