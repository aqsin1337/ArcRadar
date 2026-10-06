import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import { createAdminClient } from "@/lib/supabase/admin";
import type { SiemId } from "./constants";

/** The time of the SIEM's latest rule push as text ("" when nothing was ever pushed): the revision a SIEM host waits on. */
export async function readRevision(siem: SiemId): Promise<string> {
  const { data, error } = await createAdminClient().rpc("siem_rules_revision", { p_siem: siem });
  if (error) throw toApiError(error);
  return data ?? "";
}
