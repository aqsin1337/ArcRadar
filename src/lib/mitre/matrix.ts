import { TACTIC_ORDER, tacticKey } from "./constants";
import type {
  CatalogTechnique,
  Matrix,
  MatrixTactic,
  MatrixTechnique,
  Observation,
  ObservedRow,
} from "./types";

/*
 * The ATT&CK matrix as a page shows it: one column per tactic, the techniques under it, and on each
 * technique what this workspace's alerts say about it. Pure: it takes the catalog and the observed
 * rows and returns the structure, so the layout rules can be tested without a database.
 */

const parentOf = (id: string) => id.split(".")[0];
const isSub = (id: string) => id.includes(".");

/** `options.observedOnly` keeps only techniques an alert named (a parent stays when a child was). */
export function buildMatrix(
  catalog: readonly CatalogTechnique[],
  observed: readonly ObservedRow[],
  options: { observedOnly?: boolean } = {},
): Matrix {
  const seenBy = new Map<string, Observation>(
    observed.map((row) => [
      row.technique_id,
      { alert_count: row.alert_count, max_severity: row.max_severity, last_seen: row.last_seen },
    ]),
  );

  const byParent = new Map<string, CatalogTechnique[]>();
  for (const technique of catalog) {
    if (!isSub(technique.id)) continue;
    const list = byParent.get(parentOf(technique.id)) ?? [];
    list.push(technique);
    byParent.set(parentOf(technique.id), list);
  }

  const toCell = (technique: CatalogTechnique): MatrixTechnique => ({
    id: technique.id,
    name: technique.name,
    url: technique.url,
    observed: seenBy.get(technique.id) ?? null,
    subtechniques: (byParent.get(technique.id) ?? [])
      .map((child) => ({
        id: child.id,
        name: child.name,
        url: child.url,
        observed: seenBy.get(child.id) ?? null,
        subtechniques: [],
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  });

  // A parent is placed in its own tactics; a sub-technique follows its parent (it is listed under it).
  const columns = new Map<string, { label: string; cells: MatrixTechnique[] }>();
  const column = (label: string) => {
    const key = tacticKey(label);
    let entry = columns.get(key);
    if (!entry) {
      entry = { label, cells: [] };
      columns.set(key, entry);
    }
    return entry;
  };
  for (const label of TACTIC_ORDER) column(label);

  for (const technique of catalog) {
    if (isSub(technique.id)) continue;
    const cell = toCell(technique);
    if (options.observedOnly && !cell.observed && !cell.subtechniques.some((s) => s.observed)) {
      continue;
    }
    for (const tactic of technique.tactics) column(tactic).cells.push(cell);
  }

  const known = new Set(TACTIC_ORDER.map(tacticKey));
  const ordered = [...columns.entries()].sort(([a], [b]) => {
    const ia = known.has(a) ? TACTIC_ORDER.findIndex((t) => tacticKey(t) === a) : 1000;
    const ib = known.has(b) ? TACTIC_ORDER.findIndex((t) => tacticKey(t) === b) : 1000;
    return ia - ib || a.localeCompare(b);
  });

  const tactics: MatrixTactic[] = ordered
    .map(([key, { label, cells }]) => {
      const canonical = TACTIC_ORDER.find((t) => tacticKey(t) === key) ?? label;
      const sorted = [...cells].sort((a, b) => a.name.localeCompare(b.name));
      return {
        name: canonical,
        techniques: sorted,
        observed_techniques: sorted.filter((cell) => cell.observed).length,
      };
    })
    // A column with nothing in it (a tactic the catalog does not cover, or nothing observed) is left out.
    .filter((tactic) => tactic.techniques.length > 0);

  return {
    tactics,
    summary: {
      observed_techniques: new Set(observed.map((row) => parentOf(row.technique_id))).size,
      total_techniques: catalog.length,
    },
  };
}
