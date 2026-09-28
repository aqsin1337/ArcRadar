import "server-only";
import { ApiError, apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import { logWarn } from "@/lib/log";
import { isRoleName, roleHasPermission } from "@/lib/rbac/permissions";
import {
  API_KEY_SCOPES,
  DEFAULT_KEY_LIFETIME_DAYS,
  MAX_ACTIVE_KEYS_PER_USER,
  SCOPE_LABELS,
  SCOPE_PERMISSIONS,
  type ApiKeyScope,
} from "./constants";
import { API_KEY_PATTERN, generateApiKey, hashApiKey } from "./keys";
import {
  countUsableKeys,
  findKeyByHash,
  findVisibleApiKey,
  insertApiKey,
  listApiKeys as findApiKeys,
  revokeApiKeyRow,
  touchLastUsed,
} from "./repository";
import { apiKeyIdSchema, type CreateApiKeyInput } from "./schema";
import type { ApiKeyPrincipal, ApiKeyRow, ApiKeyStatus, ApiKeyView } from "./types";

type RequestLike = { headers: Headers };

const DAY_MS = 24 * 60 * 60 * 1000;

export function keyStatus(
  row: Pick<ApiKeyRow, "revoked_at" | "expires_at">,
  now: Date,
): ApiKeyStatus {
  if (row.revoked_at) return "revoked";
  if (row.expires_at && Date.parse(row.expires_at) <= now.getTime()) return "expired";
  return "active";
}

/** Field by field, so a column added to the query later (the hash, say) can never reach a response. */
const view = (row: ApiKeyRow, now: Date): ApiKeyView => ({
  id: row.id,
  user_id: row.user_id,
  name: row.name,
  key_prefix: row.key_prefix,
  scopes: row.scopes,
  last_used_at: row.last_used_at,
  expires_at: row.expires_at,
  revoked_at: row.revoked_at,
  created_at: row.created_at,
  status: keyStatus(row, now),
});

export async function listApiKeys(auth: AuthContext, now = new Date()): Promise<ApiKeyView[]> {
  return (await findApiKeys(auth.supabase)).map((row) => view(row, now));
}

/**
 * Makes a key for the caller and returns it: **the only time it can be read**, only its hash is kept.
 * A key can carry only scopes the caller's role may use, and a person has a limited number of usable
 * keys at once. Audited (name, scopes, prefix, expiry; never the key).
 */
export async function createApiKey(
  auth: AuthContext,
  input: CreateApiKeyInput,
  request: RequestLike,
  now = new Date(),
): Promise<{ key: string; api_key: ApiKeyView }> {
  for (const scope of input.scopes) {
    if (!auth.permissions.has(SCOPE_PERMISSIONS[scope])) {
      throw apiErrors.forbidden(
        `Your role cannot create a key that can "${SCOPE_LABELS[scope]}" (${scope}).`,
      );
    }
  }
  if ((await countUsableKeys(auth.user.id, now)) >= MAX_ACTIVE_KEYS_PER_USER) {
    throw apiErrors.conflict(
      `You already have ${MAX_ACTIVE_KEYS_PER_USER} usable API keys. Revoke one first.`,
    );
  }

  const days =
    input.expires_in_days === undefined ? DEFAULT_KEY_LIFETIME_DAYS : input.expires_in_days;
  const { key, prefix, hash } = generateApiKey();
  const row = await insertApiKey({
    user_id: auth.user.id,
    name: input.name,
    key_prefix: prefix,
    key_hash: hash,
    scopes: input.scopes,
    expires_at: days === null ? null : new Date(now.getTime() + days * DAY_MS).toISOString(),
  });

  await writeAuditLog(
    {
      action: "api_key.created",
      userId: auth.user.id,
      entityType: "api_key",
      entityId: row.id,
      metadata: {
        name: row.name,
        scopes: row.scopes,
        key_prefix: row.key_prefix,
        expires_at: row.expires_at,
      },
    },
    request,
  );
  return { key, api_key: view(row, now) };
}

/** Revokes a key the caller can see (their own, or any for an administrator). Revoking twice is harmless. */
export async function revokeApiKey(
  auth: AuthContext,
  id: string,
  request: RequestLike,
  now = new Date(),
): Promise<ApiKeyView> {
  if (!apiKeyIdSchema.safeParse(id).success) throw apiErrors.notFound("API key not found.");
  const existing = await findVisibleApiKey(auth.supabase, id);
  if (!existing) throw apiErrors.notFound("API key not found.");

  const revoked = await revokeApiKeyRow(id, now);
  if (!revoked) return view(existing, now); // it was already revoked

  await writeAuditLog(
    {
      action: "api_key.revoked",
      userId: auth.user.id,
      entityType: "api_key",
      entityId: id,
      metadata: { name: revoked.name, key_prefix: revoked.key_prefix, owner_id: revoked.user_id },
    },
    request,
  );
  return view(revoked, now);
}

const INVALID_KEY = "The API key is not valid.";

/** 401 for every reason a key cannot be used, so a caller learns nothing about which keys exist. */
const invalidKey = () =>
  new ApiError(401, "UNAUTHENTICATED", INVALID_KEY, undefined, {
    "WWW-Authenticate": 'Bearer realm="ArcRadar"',
  });

/**
 * Checks the key of a machine-facing request: well-formed, known, not revoked, not expired, owned by
 * an active account that still holds the permission behind the scope, and carrying the scope. Returns
 * who the key acts for. Any reason a key is unusable is the same 401; a valid key without the scope is 403.
 */
export async function verifyApiKey(
  token: string | null,
  scope: ApiKeyScope,
  now = new Date(),
): Promise<ApiKeyPrincipal> {
  if (!token || !API_KEY_PATTERN.test(token)) throw invalidKey();

  const row = await findKeyByHash(hashApiKey(token));
  if (!row) throw invalidKey();

  const status = keyStatus(row, now);
  const owner = row.owner;
  if (status !== "active") {
    logWarn("api_key.rejected", { key_id: row.id, reason: status });
    throw invalidKey();
  }
  if (!owner || !owner.is_active || !isRoleName(owner.role_name)) {
    logWarn("api_key.rejected", { key_id: row.id, reason: "owner_disabled" });
    throw invalidKey();
  }
  if (!roleHasPermission(owner.role_name, SCOPE_PERMISSIONS[scope])) {
    logWarn("api_key.rejected", { key_id: row.id, reason: "owner_lost_permission" });
    throw invalidKey();
  }
  if (!row.scopes.includes(scope)) {
    throw apiErrors.forbidden("This API key is not allowed to do that.");
  }

  await touchLastUsed(row.id, now).catch(() => undefined); // best effort
  return {
    keyId: row.id,
    keyName: row.name,
    keyPrefix: row.key_prefix,
    ownerId: row.user_id,
    scopes: row.scopes,
  };
}

/** Whether a string is one of the scopes a key can have. */
export const isApiKeyScope = (value: string): value is ApiKeyScope =>
  (API_KEY_SCOPES as readonly string[]).includes(value);
