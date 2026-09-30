import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient } from "@/lib/auth/context";
import { TACTIC_ORDER, tacticKey } from "@/lib/mitre/constants";
import { buildMatrix } from "@/lib/mitre/matrix";
import type { CatalogTechnique, ObservedRow } from "@/lib/mitre/types";

const repo = vi.hoisted(() => ({
  findCatalog: vi.fn(),
  findObserved: vi.fn(),
  findTechnique: vi.fn(),
  findSubtechniques: vi.fn(),
  findAlertsForTechniques: vi.fn(),
}));
vi.mock("@/lib/mitre/repository", () => repo);

const { getMatrix, getTechniqueDetail, getTopTechniques, parseTechniqueId, techniqueFilterIds } =
  await import("@/lib/mitre/service");

const supabase = {} as AuthClient;

const t = (id: string, name: string, tactics: string[]): CatalogTechnique => ({
  id,
  name,
  tactics,
  url: `https://attack.mitre.org/${id}`,
});

const catalog: CatalogTechnique[] = [
  t("T1110", "Brute Force", ["Credential Access"]),
  t("T1110.001", "Password Guessing", ["Credential Access"]),
  t("T1110.003", "Password Spraying", ["Credential Access"]),
  t("T1059", "Command and Scripting Interpreter", ["Execution"]),
  t("T1078", "Valid Accounts", ["Initial Access", "Persistence", "Defense Evasion"]),
  t("T1102", "Web Service", ["Command And Control"]),
  t("T1595", "Active Scanning", ["Reconnaissance"]),
  t("T9999", "Odd Tactic Technique", ["Made Up Tactic"]),
];

const seen = (
  technique_id: string,
  alert_count: number,
  max_severity: ObservedRow["max_severity"] = "high",
): ObservedRow => ({ technique_id, alert_count, max_severity, last_seen: "2026-09-30T08:00:00Z" });

describe("buildMatrix", () => {
  const matrix = buildMatrix(catalog, [seen("T1110", 3), seen("T1110.003", 2, "medium")]);
  const column = (name: string) => matrix.tactics.find((tactic) => tactic.name === name);

  it("orders the columns the way an attack unfolds and puts an unknown tactic last", () => {
    const names = matrix.tactics.map((tactic) => tactic.name);
    const known = TACTIC_ORDER.filter((name) => names.includes(name));
    expect(names.slice(0, known.length)).toEqual(known);
    expect(names.at(-1)).toBe("Made Up Tactic");
  });

  it("puts a technique in every tactic it belongs to, and names the tactics one way", () => {
    for (const name of ["Initial Access", "Persistence", "Defense Evasion"]) {
      expect(column(name)?.techniques.map((c) => c.id)).toContain("T1078");
    }
    // "Command And Control" (as an older import wrote it) lands in the "Command and Control" column.
    expect(column("Command and Control")?.techniques.map((c) => c.id)).toEqual(["T1102"]);
    expect(
      matrix.tactics.filter((tactic) => tacticKey(tactic.name) === "command and control"),
    ).toHaveLength(1);
  });

  it("lists sub-techniques under their parent, not as columns entries of their own", () => {
    const parent = column("Credential Access")?.techniques[0];
    expect(parent?.id).toBe("T1110");
    expect(parent?.subtechniques.map((s) => s.id)).toEqual(["T1110.001", "T1110.003"]);
    expect(column("Credential Access")?.techniques).toHaveLength(1);
  });

  it("carries what the alerts say on each technique, null where nothing was seen", () => {
    const parent = column("Credential Access")?.techniques[0];
    expect(parent?.observed).toEqual({
      alert_count: 3,
      max_severity: "high",
      last_seen: "2026-09-30T08:00:00Z",
    });
    expect(parent?.subtechniques.find((s) => s.id === "T1110.003")?.observed).toMatchObject({
      alert_count: 2,
      max_severity: "medium",
    });
    expect(parent?.subtechniques.find((s) => s.id === "T1110.001")?.observed).toBeNull();
    expect(column("Execution")?.techniques[0].observed).toBeNull();
  });

  it("counts observed techniques per column and overall (a sub-technique counts as its parent)", () => {
    expect(column("Credential Access")?.observed_techniques).toBe(1);
    expect(column("Execution")?.observed_techniques).toBe(0);
    expect(matrix.summary).toEqual({ observed_techniques: 1, total_techniques: catalog.length });
  });

  it("can keep only what was seen, dropping empty columns; a parent stays when a child was seen", () => {
    const only = buildMatrix(catalog, [seen("T1110.003", 1)], { observedOnly: true });
    expect(only.tactics.map((tactic) => tactic.name)).toEqual(["Credential Access"]);
    expect(only.tactics[0].techniques.map((c) => c.id)).toEqual(["T1110"]);
  });

  it("gives an empty matrix for an empty catalog, and everything unobserved for no alerts", () => {
    expect(buildMatrix([], [])).toEqual({
      tactics: [],
      summary: { observed_techniques: 0, total_techniques: 0 },
    });
    const quiet = buildMatrix(catalog, []);
    expect(quiet.summary.observed_techniques).toBe(0);
    expect(quiet.tactics.every((tactic) => tactic.observed_techniques === 0)).toBe(true);
  });
});

describe("parseTechniqueId", () => {
  it("accepts technique and sub-technique ids in any case, and nothing else", () => {
    expect(parseTechniqueId("t1078.001")).toBe("T1078.001");
    expect(parseTechniqueId(" T1566 ")).toBe("T1566");
    for (const bad of ["", "T12", "1566", "T1566.1", "T1566.001.002", "../etc", "T1566;drop"]) {
      expect(parseTechniqueId(bad)).toBeNull();
    }
  });
});

describe("service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    repo.findCatalog.mockResolvedValue(catalog);
    repo.findObserved.mockResolvedValue([
      seen("T1110", 3),
      seen("T1110.003", 2, "medium"),
      seen("T1059", 5, "low"),
    ]);
  });

  it("getMatrix builds from the catalog and the observed rows the caller can see", async () => {
    const matrix = await getMatrix(supabase);
    expect(matrix.summary.observed_techniques).toBe(2);
    expect((await getMatrix(supabase, { observedOnly: true })).tactics.map((x) => x.name)).toEqual([
      "Execution",
      "Credential Access",
    ]);
  });

  it("getTopTechniques ranks top-level techniques by alerts and names them", async () => {
    expect(await getTopTechniques(supabase, 5)).toEqual([
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        alert_count: 5,
        max_severity: "low",
      },
      { id: "T1110", name: "Brute Force", alert_count: 3, max_severity: "high" },
    ]);
    expect(await getTopTechniques(supabase, 1)).toHaveLength(1);
    repo.findObserved.mockResolvedValue([]);
    expect(await getTopTechniques(supabase, 5)).toEqual([]);
    expect(repo.findCatalog).toHaveBeenCalledTimes(2); // not asked when nothing was observed
  });

  it("getTechniqueDetail answers 404 for a malformed or unknown id, without touching the database for a bad one", async () => {
    await expect(getTechniqueDetail(supabase, "nope")).rejects.toMatchObject({ status: 404 });
    expect(repo.findTechnique).not.toHaveBeenCalled();
    repo.findTechnique.mockResolvedValue(null);
    await expect(getTechniqueDetail(supabase, "T4242")).rejects.toMatchObject({ status: 404 });
  });

  it("getTechniqueDetail reads a parent with its sub-techniques and the alerts naming any of them", async () => {
    repo.findTechnique.mockResolvedValue({ ...catalog[0], description: "Guessing passwords." });
    repo.findSubtechniques.mockResolvedValue([
      { id: "T1110.001", name: "Password Guessing" },
      { id: "T1110.003", name: "Password Spraying" },
    ]);
    repo.findAlertsForTechniques.mockResolvedValue({ alerts: [{ id: "a1" }], total: 4 });

    const detail = await getTechniqueDetail(supabase, "t1110");
    expect(repo.findAlertsForTechniques).toHaveBeenCalledWith(
      supabase,
      ["T1110", "T1110.001", "T1110.003"],
      25,
    );
    expect(detail).toMatchObject({
      id: "T1110",
      parent_id: null,
      description: "Guessing passwords.",
      alert_total: 4,
      observed: { alert_count: 3, max_severity: "high" },
    });
    expect(detail.subtechniques.map((s) => s.id)).toEqual(["T1110.001", "T1110.003"]);
  });

  it("getTechniqueDetail names the parent of a sub-technique and finds nothing observed for a quiet one", async () => {
    repo.findTechnique.mockResolvedValue({ ...catalog[1], description: null });
    repo.findSubtechniques.mockResolvedValue([]);
    repo.findAlertsForTechniques.mockResolvedValue({ alerts: [], total: 0 });
    const detail = await getTechniqueDetail(supabase, "T1110.001");
    expect(detail.parent_id).toBe("T1110");
    expect(detail.observed).toBeNull();
    expect(repo.findAlertsForTechniques).toHaveBeenCalledWith(supabase, ["T1110.001"], 25);
  });

  it("techniqueFilterIds expands a parent to its children, and a sub-technique or a bad id to itself or nothing", async () => {
    repo.findSubtechniques.mockResolvedValue([{ id: "T1110.001", name: "x" }]);
    expect(await techniqueFilterIds(supabase, "T1110")).toEqual(["T1110", "T1110.001"]);
    expect(await techniqueFilterIds(supabase, "T1110.001")).toEqual(["T1110.001"]);
    expect(repo.findSubtechniques).toHaveBeenCalledTimes(1);
    expect(await techniqueFilterIds(supabase, "bad")).toEqual([]);
  });
});
