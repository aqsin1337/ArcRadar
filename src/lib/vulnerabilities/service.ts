import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { getServerEnv, type ServerEnv } from "@/lib/env/server";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { logError, logWarn } from "@/lib/log";
import { ProviderError } from "@/lib/intel/types";
import type { Vulnerability } from "@/types/domain";
import { NvdProvider } from "./nvd";
import {
  findSeverityStats,
  findVulnerabilities,
  findVulnerabilityDetail,
  findVulnerabilityOrigin,
  importExternalVulnerability,
} from "./repository";
import { isCveId, type VulnerabilityListQuery } from "./schema";
import type {
  VulnerabilityDetail,
  VulnerabilityProvider,
  VulnerabilityRecord,
  VulnerabilityStats,
} from "./types";

type RequestLike = { headers: Headers };

export const IMPORT_TIMEOUT_MS = 10_000;

/** The connected vulnerability provider: NVD when its key is set, otherwise none. */
export function getVulnerabilityProvider(
  env: Pick<ServerEnv, "NVD_API_KEY"> = getServerEnv(),
  fetchImpl?: typeof fetch,
): VulnerabilityProvider | null {
  return env.NVD_API_KEY ? new NvdProvider({ apiKey: env.NVD_API_KEY, fetchImpl }) : null;
}

export async function listVulnerabilities(
  supabase: AuthClient,
  query: VulnerabilityListQuery,
): Promise<Page<Vulnerability>> {
  const { rows, total } = await findVulnerabilities(supabase, query);
  return buildPage(rows, total, query);
}

export function getVulnerabilityStats(supabase: AuthClient): Promise<VulnerabilityStats> {
  return findSeverityStats(supabase);
}

export async function getVulnerability(
  supabase: AuthClient,
  cveId: string,
): Promise<VulnerabilityDetail> {
  const id = cveId.toUpperCase();
  if (!isCveId(id)) throw apiErrors.notFound("Vulnerability not found.");
  const detail = await findVulnerabilityDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Vulnerability not found.");
  return detail;
}

export type ImportResult = { vulnerability: VulnerabilityDetail; created: boolean };

export type ImportDeps = {
  provider: VulnerabilityProvider | null;
  now: () => Date;
  timeoutMs: number;
  audit: typeof writeAuditLog;
  store: typeof importExternalVulnerability;
};

export async function defaultImportDeps(): Promise<ImportDeps> {
  return {
    provider: await resolveVulnerabilityProvider(),
    now: () => new Date(),
    timeoutMs: IMPORT_TIMEOUT_MS,
    audit: writeAuditLog,
    store: importExternalVulnerability,
  };
}

/**
 * Fetches a CVE from the connected provider and records it as external data (or refreshes the
 * external record that is already there). Needs vulnerabilities:write, which the route guard checks
 * first; nothing is stored unless the provider answered, and demo or local records are never replaced.
 */
export async function importVulnerability(
  auth: AuthContext,
  cveId: string,
  request: RequestLike,
  providedDeps?: ImportDeps,
): Promise<ImportResult> {
  const deps = providedDeps ?? (await defaultImportDeps());
  const id = cveId.toUpperCase();
  if (!isCveId(id))
    throw apiErrors.validation({
      issues: [{ path: "cve_id", message: "Enter a CVE id such as CVE-2021-44228." }],
    });
  if (!deps.provider) {
    throw apiErrors.unavailable(
      "No vulnerability provider is connected. An administrator can connect NVD by setting its API key on the server.",
    );
  }

  const existing = await findVulnerabilityOrigin(auth.supabase, id);
  if (existing && existing !== "external") {
    throw apiErrors.conflict(
      "This CVE already exists as demo or local data, so it was not replaced.",
    );
  }

  const provider = deps.provider;
  let record: VulnerabilityRecord | null;
  try {
    record = await provider.lookupCve(id, {
      signal: AbortSignal.timeout(deps.timeoutMs),
      now: deps.now(),
    });
  } catch (error) {
    if (!(error instanceof ProviderError)) {
      logError("vulnerability.provider_error", error, { provider: provider.info.id });
      throw apiErrors.unavailable(`${provider.info.name} could not be reached.`);
    }
    logWarn("vulnerability.provider_failed", { provider: provider.info.id, reason: error.reason });
    if (error.reason === "rate_limited")
      throw apiErrors.rateLimited(error.retryAfterSeconds ?? undefined);
    throw apiErrors.unavailable(`${provider.info.name}: ${error.message}`);
  }
  if (!record) throw apiErrors.notFound(`${provider.info.name} has no record of ${id}.`);

  await deps.store(record);
  await deps.audit(
    {
      action: "vulnerability.imported",
      userId: auth.user.id,
      entityType: "vulnerability",
      entityId: id,
      metadata: { provider: provider.info.id, refreshed: existing === "external" },
    },
    request,
  );
  return { vulnerability: await getVulnerability(auth.supabase, id), created: existing === null };
}

/** Like getVulnerabilityProvider, but also sees an NVD key an administrator saved in the app. */
export async function resolveVulnerabilityProvider(
  fetchImpl?: typeof fetch,
): Promise<VulnerabilityProvider | null> {
  return getVulnerabilityProvider(await getEffectiveEnv(), fetchImpl);
}
