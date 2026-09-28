import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";
import { createAdminClient } from "@/lib/supabase/admin";
import { LAST_USED_REFRESH_SECONDS } from "./constants";
import type { ApiKeyRow } from "./types";

/*
 * Reads for people use the caller's own client (row level security shows a person their own keys, an
 * administrator all of them; the key hash is not even a readable column). Everything that creates,
 * revokes or verifies a key uses the service role, after the service has authorized the caller.
 */

const COLUMNS =
  "id, user_id, name, key_prefix, scopes, last_used_at, expires_at, revoked_at, created_at";

export async function listApiKeys(supabase: AuthClient): Promise<ApiKeyRow[]> {
  const { data, error } = await supabase
    .from("api_keys")
    .select(COLUMNS)
    .order("created_at", { ascending: false });
  if (error) throw toApiError(error);
  return data;
}

export async function findVisibleApiKey(
  supabase: AuthClient,
  id: string,
): Promise<ApiKeyRow | null> {
  const { data, error } = await supabase
    .from("api_keys")
    .select(COLUMNS)
    .eq("id", id)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** How many keys of this person can still be used (not revoked, not expired). */
export async function countUsableKeys(userId: string, now: Date): Promise<number> {
  const { count, error } = await createAdminClient()
    .from("api_keys")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .is("revoked_at", null)
    .or(`expires_at.is.null,expires_at.gt.${now.toISOString()}`);
  if (error) throw toApiError(error);
  return count ?? 0;
}

export async function insertApiKey(row: {
  user_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: string[];
  expires_at: string | null;
}): Promise<ApiKeyRow> {
  const { data, error } = await createAdminClient()
    .from("api_keys")
    .insert(row)
    .select(COLUMNS)
    .single();
  if (error) throw toApiError(error);
  return data;
}

/** Marks a key revoked (once: revoking again keeps the first time). `null` when it is already revoked. */
export async function revokeApiKeyRow(id: string, now: Date): Promise<ApiKeyRow | null> {
  const { data, error } = await createAdminClient()
    .from("api_keys")
    .update({ revoked_at: now.toISOString() })
    .eq("id", id)
    .is("revoked_at", null)
    .select(COLUMNS)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

export type KeyWithOwner = ApiKeyRow & {
  owner: { is_active: boolean; role_name: string } | null;
};

/** The key with this hash and the account that owns it, for verifying a request. */
export async function findKeyByHash(hash: string): Promise<KeyWithOwner | null> {
  const { data, error } = await createAdminClient()
    .from("api_keys")
    .select(`${COLUMNS}, owner:profiles!user_id(is_active, role_name)`)
    .eq("key_hash", hash)
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}

/** Records that a key was used, at most once a minute. Best effort: the caller ignores a failure. */
export async function touchLastUsed(id: string, now: Date): Promise<void> {
  const stale = new Date(now.getTime() - LAST_USED_REFRESH_SECONDS * 1000).toISOString();
  const { error } = await createAdminClient()
    .from("api_keys")
    .update({ last_used_at: now.toISOString() })
    .eq("id", id)
    .or(`last_used_at.is.null,last_used_at.lt.${stale}`);
  if (error) throw toApiError(error);
}
