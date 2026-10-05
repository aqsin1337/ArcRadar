import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import type { AuthClient } from "@/lib/auth/context";
import type { ServerEnv } from "@/lib/env/server";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { FEED_GROUPS } from "@/lib/feeds/groups";
import { INTEGRATION_PROVIDERS, PROVIDER_ENV_KEYS } from "./constants";
import { findDisabledProviders, findIntegrationRows, updateIntegrationEnabled } from "./repository";
import type { IntegrationRow } from "./types";

type RequestLike = { headers: Headers };

/**
 * demo always works with no key; wazuh is configured per API key, not one shared server secret; the
 * public feeds (abuse.ch, CISA KEV) are free and need no key at all.
 */
function isConfigured(provider: string, env: ServerEnv): boolean {
  if (
    provider === "demo" ||
    provider === "wazuh" ||
    (FEED_GROUPS as readonly string[]).includes(provider)
  ) {
    return true;
  }
  const key = PROVIDER_ENV_KEYS[provider as keyof typeof PROVIDER_ENV_KEYS];
  return key !== undefined && Boolean(env[key]);
}

export async function getIntegrations(
  supabase: AuthClient,
  env?: ServerEnv,
): Promise<IntegrationRow[]> {
  const [rows, effective] = await Promise.all([
    findIntegrationRows(supabase),
    env ? Promise.resolve(env) : getEffectiveEnv(),
  ]);
  return rows.map((row) => ({ ...row, configured: isConfigured(row.provider, effective) }));
}

/**
 * Providers a lookup should skip even though a key is configured: an administrative pause, on top
 * of (never instead of) the key check. Used only where a live call is about to be made.
 */
export const findDisabledLookupProviders = findDisabledProviders;

export async function setIntegrationEnabled(
  auth: AuthContext,
  provider: string,
  enabled: boolean,
  request: RequestLike,
): Promise<IntegrationRow> {
  if (!(INTEGRATION_PROVIDERS as readonly string[]).includes(provider)) {
    throw apiErrors.notFound("Integration not found.");
  }
  if (provider === "demo" && !enabled) {
    throw apiErrors.conflict("The demo provider is always available and cannot be turned off.");
  }

  const row = await updateIntegrationEnabled(auth.supabase, provider, enabled);
  if (!row) throw apiErrors.notFound("Integration not found.");

  await writeAuditLog(
    {
      action: "integration.updated",
      userId: auth.user.id,
      entityType: "integration",
      entityId: provider,
      metadata: { enabled },
    },
    request,
  );

  return { ...row, configured: isConfigured(provider, await getEffectiveEnv()) };
}
