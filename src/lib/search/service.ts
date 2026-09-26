import "server-only";
import { z } from "zod";
import type { AuthContext } from "@/lib/auth/context";
import {
  INDICATOR_TYPE_SHORT_LABELS,
  SEVERITY_LABELS,
  VERDICT_LABELS,
} from "@/lib/indicators/constants";
import { findIndicators } from "@/lib/indicators/repository";
import { indicatorListQuerySchema } from "@/lib/indicators/schema";
import type { Permission } from "@/lib/rbac/permissions";
import type { DataOrigin } from "@/types/domain";

/** Query string of GET /api/search. */
export const searchQuerySchema = z.object({
  q: z.string().trim().min(2, "Type at least 2 characters.").max(200),
  limit: z.coerce.number().int().min(1).max(10).default(6),
});

export type SearchHit = {
  id: string;
  title: string;
  subtitle: string;
  href: string;
  /** Provenance, so the UI can label demo and local results. */
  origin: DataOrigin;
};

export type SearchGroup = { kind: string; label: string; total: number; hits: SearchHit[] };
export type SearchResults = { query: string; groups: SearchGroup[] };

type SearchSource = {
  kind: string;
  label: string;
  /** Sources are skipped for callers without this permission (RLS would return nothing anyway). */
  permission: Permission;
  search: (
    auth: AuthContext,
    query: string,
    limit: number,
  ) => Promise<Omit<SearchGroup, "kind" | "label">>;
};

// One entry per searchable record type. Add threat actors, vulnerabilities, alerts and so on here as
// their pages ship: a hit needs a `href` that exists.
const SOURCES: SearchSource[] = [
  {
    kind: "indicator",
    label: "Indicators",
    permission: "indicators:read",
    async search(auth, query, limit) {
      const { rows, total } = await findIndicators(
        auth.supabase,
        indicatorListQuerySchema.parse({ q: query, page: 1, page_size: limit }),
      );
      return {
        total,
        hits: rows.map((row) => ({
          id: row.id,
          title: row.value,
          subtitle: [
            INDICATOR_TYPE_SHORT_LABELS[row.type],
            VERDICT_LABELS[row.verdict],
            SEVERITY_LABELS[row.severity],
          ].join(" · "),
          href: `/indicators/${row.id}`,
          origin: row.origin,
        })),
      };
    },
  },
];

/** Searches every source the caller may read, in parallel. Sources with no hits are left out. */
export async function globalSearch(
  auth: AuthContext,
  query: string,
  limit: number,
): Promise<SearchResults> {
  const allowed = SOURCES.filter((source) => auth.permissions.has(source.permission));
  const groups = await Promise.all(
    allowed.map(async (source) => ({
      kind: source.kind,
      label: source.label,
      ...(await source.search(auth, query, limit)),
    })),
  );
  return { query, groups: groups.filter((group) => group.hits.length > 0) };
}
