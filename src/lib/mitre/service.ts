import "server-only";
import { z } from "zod";
import { apiErrors } from "@/lib/api/errors";
import type { AuthClient } from "@/lib/auth/context";
import type { Alert } from "@/types/domain";
import { TECHNIQUE_ID } from "./constants";
import { buildMatrix } from "./matrix";
import {
  findAlertsForTechniques,
  findCatalog,
  findObserved,
  findSubtechniques,
  findTechnique,
} from "./repository";
import type { Matrix, Observation } from "./types";

export const techniqueIdSchema = z
  .string()
  .trim()
  .transform((id) => id.toUpperCase())
  .pipe(z.string().regex(TECHNIQUE_ID, "A technique id looks like T1566 or T1078.001."));

/** The id in canonical form (T1078.001), or null when it is not a technique id. */
export function parseTechniqueId(id: string): string | null {
  const parsed = techniqueIdSchema.safeParse(id);
  return parsed.success ? parsed.data : null;
}

export async function getMatrix(
  supabase: AuthClient,
  options: { observedOnly?: boolean } = {},
): Promise<Matrix> {
  const [catalog, observed] = await Promise.all([findCatalog(supabase), findObserved(supabase)]);
  return buildMatrix(catalog, observed, options);
}

export type TechniqueDetail = {
  id: string;
  name: string;
  description: string | null;
  tactics: string[];
  url: string | null;
  parent_id: string | null;
  subtechniques: { id: string; name: string }[];
  observed: Observation | null;
  /** The newest alerts naming this technique (or, for a parent, any of its sub-techniques). */
  alerts: Alert[];
  alert_total: number;
};

const ALERT_LIMIT = 25;

export async function getTechniqueDetail(
  supabase: AuthClient,
  rawId: string,
): Promise<TechniqueDetail> {
  const id = parseTechniqueId(rawId);
  if (!id) throw apiErrors.notFound("Technique not found.");
  const technique = await findTechnique(supabase, id);
  if (!technique) throw apiErrors.notFound("Technique not found.");

  const subtechniques = await findSubtechniques(supabase, id);
  const [observed, found] = await Promise.all([
    findObserved(supabase),
    findAlertsForTechniques(supabase, [id, ...subtechniques.map((s) => s.id)], ALERT_LIMIT),
  ]);
  const row = observed.find((entry) => entry.technique_id === id);
  return {
    id: technique.id,
    name: technique.name,
    description: technique.description,
    tactics: technique.tactics,
    url: technique.url,
    parent_id: id.includes(".") ? id.split(".")[0] : null,
    subtechniques,
    observed: row
      ? { alert_count: row.alert_count, max_severity: row.max_severity, last_seen: row.last_seen }
      : null,
    alerts: found.alerts,
    alert_total: found.total,
  };
}

/** The technique ids an alert filter by `technique` should match: the id and, for a parent, its children. */
export async function techniqueFilterIds(supabase: AuthClient, rawId: string): Promise<string[]> {
  const id = parseTechniqueId(rawId);
  if (!id) return [];
  const children = id.includes(".") ? [] : await findSubtechniques(supabase, id);
  return [id, ...children.map((child) => child.id)];
}

export type TopTechnique = {
  id: string;
  name: string;
  alert_count: number;
  max_severity: Observation["max_severity"];
};

/** The techniques (top-level ones; a sub-technique counts for its parent) named by the most alerts. */
export async function getTopTechniques(
  supabase: AuthClient,
  limit: number,
): Promise<TopTechnique[]> {
  const observed = (await findObserved(supabase))
    .filter((row) => !row.technique_id.includes("."))
    .sort((a, b) => b.alert_count - a.alert_count || b.last_seen.localeCompare(a.last_seen))
    .slice(0, limit);
  if (observed.length === 0) return [];
  const catalog = await findCatalog(supabase);
  const names = new Map(catalog.map((technique) => [technique.id, technique.name]));
  return observed.map((row) => ({
    id: row.technique_id,
    name: names.get(row.technique_id) ?? row.technique_id,
    alert_count: row.alert_count,
    max_severity: row.max_severity,
  }));
}
