import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import { createAdminClient } from "@/lib/supabase/admin";

/*
 * provider_secrets is closed to every client role; only the service role reads or writes it, and
 * only the service in this folder calls it, after authorizing the caller (or, for reading values
 * back into the environment, on the server only).
 */

export type StoredSecret = {
  name: string;
  ciphertext: string;
  last4: string | null;
  updated_at: string;
};

export async function findStoredSecrets(): Promise<StoredSecret[]> {
  const { data, error } = await createAdminClient()
    .from("provider_secrets")
    .select("name, ciphertext, last4, updated_at");
  if (error) throw toApiError(error);
  return data;
}

export async function upsertStoredSecret(row: {
  name: string;
  ciphertext: string;
  last4: string | null;
  updated_by: string;
}): Promise<void> {
  const { error } = await createAdminClient()
    .from("provider_secrets")
    .upsert({ ...row, updated_at: new Date().toISOString() }, { onConflict: "name" });
  if (error) throw toApiError(error);
}

export async function deleteStoredSecret(name: string): Promise<void> {
  const { error } = await createAdminClient().from("provider_secrets").delete().eq("name", name);
  if (error) throw toApiError(error);
}
