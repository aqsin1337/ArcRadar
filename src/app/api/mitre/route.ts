import { z } from "zod";
import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseQuery } from "@/lib/api/validate";
import { getMatrix } from "@/lib/mitre/service";

export const dynamic = "force-dynamic";

const querySchema = z.object({ observed: z.enum(["1"]).optional() });

/**
 * GET /api/mitre[?observed=1]
 * The ATT&CK matrix: one entry per tactic (in attack order) with its techniques and their
 * sub-techniques, and on each technique what this workspace's alerts say about it (`observed`: how
 * many alerts, the worst severity, the latest one; null when no alert names it). `observed=1` keeps
 * only what was observed. Needs threat_intel:read.
 */
export const GET = protectedRoute(
  { permissions: ["threat_intel:read"] },
  async ({ request, auth }) => {
    const { observed } = parseQuery(request, querySchema);
    return ok(await getMatrix(auth.supabase, { observedOnly: observed === "1" }));
  },
);
