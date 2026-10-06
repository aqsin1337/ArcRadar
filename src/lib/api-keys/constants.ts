import type { Permission } from "@/lib/rbac/permissions";

/** Every key starts with this, so a leaked one is recognizable (and secret scanners can find it). */
export const API_KEY_PREFIX = "arc_";

/** What a key may be used for. Add a scope here when a new machine-facing endpoint arrives. */
export const API_KEY_SCOPES = ["ingest:wazuh", "ingest:splunk"] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];

export const SCOPE_LABELS: Record<ApiKeyScope, string> = {
  "ingest:wazuh": "Send Wazuh alerts to ArcRadar",
  "ingest:splunk": "Send Splunk alerts to ArcRadar",
};

/**
 * The permission a person needs for a key to carry a scope. It is checked when the key is created
 * and again on every request, so a key stops working the day its owner is disabled or demoted.
 */
export const SCOPE_PERMISSIONS: Record<ApiKeyScope, Permission> = {
  "ingest:wazuh": "events:write",
  "ingest:splunk": "events:write",
};

export const MAX_ACTIVE_KEYS_PER_USER = 10;
export const MAX_KEY_LIFETIME_DAYS = 365;
/** A key made without an explicit lifetime expires after this long. */
export const DEFAULT_KEY_LIFETIME_DAYS = 365;

/** `last_used_at` is refreshed at most this often, so a busy sensor does not write on every request. */
export const LAST_USED_REFRESH_SECONDS = 60;
