import "server-only";
import { z } from "zod";
import type { AuthContext } from "@/lib/auth/context";
import {
  INDICATOR_TYPE_SHORT_LABELS,
  SEVERITY_LABELS,
  VERDICT_LABELS,
} from "@/lib/indicators/constants";
import { ALERT_STATUS_LABELS } from "@/lib/alerts/constants";
import { findAlerts } from "@/lib/alerts/repository";
import { alertListQuerySchema } from "@/lib/alerts/schema";
import { findIndicators } from "@/lib/indicators/repository";
import { indicatorListQuerySchema } from "@/lib/indicators/schema";
import { INTEL_KIND_LABELS, INTEL_SUBJECT_LABELS, intelHref } from "@/lib/intel/constants";
import { detectKind } from "@/lib/intel/target";
import { INVESTIGATION_STATUS_LABELS, PRIORITY_LABELS } from "@/lib/investigations/constants";
import { findInvestigations } from "@/lib/investigations/repository";
import { investigationListQuerySchema } from "@/lib/investigations/schema";
import type { Permission } from "@/lib/rbac/permissions";
import { searchTechniques } from "@/lib/mitre/repository";
import { findVulnerabilities } from "@/lib/vulnerabilities/repository";
import { vulnerabilityListQuerySchema } from "@/lib/vulnerabilities/schema";
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
  /** Provenance, so the UI can label demo and local results. Null for actions that are not records. */
  origin: DataOrigin | null;
  /** The title is a value (an indicator, a CVE id, a technique id) and reads better in monospace. */
  mono?: boolean;
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

// One entry per searchable record type. A hit needs a `href` that exists, so add a source here when
// its page ships. Each source searches with the same query schema and repository as its list page.
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
          mono: true,
        })),
      };
    },
  },
  {
    kind: "vulnerability",
    label: "Vulnerabilities",
    permission: "vulnerabilities:read",
    async search(auth, query, limit) {
      const { rows, total } = await findVulnerabilities(
        auth.supabase,
        vulnerabilityListQuerySchema.parse({ q: query, page: 1, page_size: limit }),
      );
      return {
        total,
        hits: rows.map((row) => ({
          id: row.id,
          title: row.cve_id,
          subtitle: [
            SEVERITY_LABELS[row.severity],
            row.cvss_score === null ? "Not scored" : `CVSS ${row.cvss_score.toFixed(1)}`,
            row.title,
          ].join(" · "),
          href: `/vulnerabilities/${row.cve_id}`,
          origin: row.origin,
          mono: true,
        })),
      };
    },
  },
  {
    kind: "alert",
    label: "Alerts",
    permission: "alerts:read",
    async search(auth, query, limit) {
      const { rows, total } = await findAlerts(
        auth.supabase,
        alertListQuerySchema.parse({ q: query, page: 1, page_size: limit }),
        auth.user.id,
      );
      return {
        total,
        hits: rows.map((row) => ({
          id: row.id,
          title: row.title,
          subtitle: [
            SEVERITY_LABELS[row.severity],
            ALERT_STATUS_LABELS[row.status],
            row.source,
          ].join(" · "),
          href: `/alerts/${row.id}`,
          origin: row.origin,
        })),
      };
    },
  },
  {
    kind: "investigation",
    label: "Investigations",
    permission: "investigations:read",
    async search(auth, query, limit) {
      const { rows, total } = await findInvestigations(
        auth.supabase,
        investigationListQuerySchema.parse({ q: query, page: 1, page_size: limit }),
        auth.user.id,
      );
      return {
        total,
        hits: rows.map((row) => ({
          id: row.id,
          title: row.title,
          subtitle: [INVESTIGATION_STATUS_LABELS[row.status], PRIORITY_LABELS[row.priority]].join(
            " · ",
          ),
          href: `/investigations/${row.id}`,
          origin: row.origin,
        })),
      };
    },
  },
  {
    kind: "technique",
    label: "MITRE ATT&CK",
    permission: "threat_intel:read",
    async search(auth, query, limit) {
      const { rows, total } = await searchTechniques(auth.supabase, query, limit);
      return {
        total,
        hits: rows.map((row) => ({
          id: row.id,
          title: `${row.id} ${row.name}`,
          subtitle: row.tactics.join(", ") || "Technique",
          href: `/mitre/${row.id}`,
          // Reference data from the public ATT&CK catalog, not a record of this workspace's own.
          origin: null,
          mono: true,
        })),
      };
    },
  },
];

/**
 * When the text is, by structure alone, an IP address, domain, URL or file hash, offer to look it
 * up. This recognizes the shape of a value; it says nothing about whether the value is malicious.
 */
function lookupSuggestion(auth: AuthContext, query: string): SearchGroup | null {
  if (!auth.permissions.has("indicators:read")) return null;
  const detected = detectKind(query);
  if (!detected || detected.kind === "cve") return null;
  return {
    kind: "lookup",
    label: "Look up",
    total: 1,
    hits: [
      {
        id: `lookup:${detected.kind}`,
        title: detected.value,
        subtitle: `Open ${INTEL_KIND_LABELS[detected.kind]} for this ${INTEL_SUBJECT_LABELS[detected.kind]}`,
        href: intelHref(detected.kind, detected.value),
        origin: null,
      },
    ],
  };
}

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
  const suggestion = lookupSuggestion(auth, query);
  return {
    query,
    groups: [
      ...(suggestion ? [suggestion] : []),
      ...groups.filter((group) => group.hits.length > 0),
    ],
  };
}
