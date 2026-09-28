import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import type { AuthClient } from "@/lib/auth/context";

type Row = {
  provider: string;
  display_name: string;
  capabilities: string[];
  enabled: boolean;
  last_sync_at: string | null;
};

export async function findIntegrationRows(supabase: AuthClient): Promise<Row[]> {
  const { data, error } = await supabase
    .from("integrations")
    .select("provider, display_name, capabilities, enabled, last_sync_at")
    .order("provider");
  if (error) throw toApiError(error);
  return data;
}

/** The providers an administrator has turned off (regardless of whether a key is configured). */
export async function findDisabledProviders(supabase: AuthClient): Promise<Set<string>> {
  const { data, error } = await supabase
    .from("integrations")
    .select("provider")
    .eq("enabled", false);
  if (error) throw toApiError(error);
  return new Set(data.map((row) => row.provider));
}

/** The updated row, or null when the provider does not exist. */
export async function updateIntegrationEnabled(
  supabase: AuthClient,
  provider: string,
  enabled: boolean,
): Promise<Row | null> {
  const { data, error } = await supabase
    .from("integrations")
    .update({ enabled })
    .eq("provider", provider)
    .select("provider, display_name, capabilities, enabled, last_sync_at")
    .maybeSingle();
  if (error) throw toApiError(error);
  return data;
}
