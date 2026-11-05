import "server-only";
import { toApiError } from "@/lib/api/supabase-errors";
import { createAdminClient } from "@/lib/supabase/admin";
import type { SiemId } from "./constants";

/** A rule host that waits for pushes: a SIEM from `siem_rules`, or the Wazuh Manager (its own `wazuh_rules`). */
export type WakeTarget = SiemId | "wazuh";

/** The time of the target's latest rule push as text ("" when nothing was ever pushed): the revision a rule host waits on. */
export async function readRevision(target: WakeTarget): Promise<string> {
  if (target === "wazuh") {
    // A Wazuh rule is never withdrawn (only a draft can be rejected), so the latest push is the whole revision.
    const { data, error } = await createAdminClient()
      .from("wazuh_rules")
      .select("pushed_at")
      .not("pushed_at", "is", null)
      .order("pushed_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) throw toApiError(error);
    return data?.pushed_at ?? "";
  }
  const { data, error } = await createAdminClient().rpc("siem_rules_revision", { p_siem: target });
  if (error) throw toApiError(error);
  return data ?? "";
}
