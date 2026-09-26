import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import { logError } from "@/lib/log";
import type { AuditAction } from "./actions";
import { getRequestMeta } from "./request-meta";
import { sanitizeMetadata } from "./sanitize";

export type AuditEntry = {
  action: AuditAction;
  /** Acting user, or null/omitted when there is none (failed login, anonymous request). */
  userId?: string | null;
  entityType?: string;
  entityId?: string;
  metadata?: Record<string, unknown>;
};

/**
 * Appends one row to audit_logs. Only the service role can write there, so this is the single
 * write path; call it from server code after the action it records has been authorized.
 *
 * It never throws: a broken audit backend must not turn a successful request into an error. The
 * failure is logged and `false` is returned so callers that must fail closed can check it.
 */
export async function writeAuditLog(
  entry: AuditEntry,
  request?: { headers: Headers },
): Promise<boolean> {
  try {
    const { ip, userAgent } = getRequestMeta(request);
    const { error } = await createAdminClient()
      .from("audit_logs")
      .insert({
        action: entry.action,
        user_id: entry.userId ?? null,
        entity_type: entry.entityType ?? null,
        entity_id: entry.entityId ?? null,
        ip_address: ip,
        user_agent: userAgent,
        metadata: sanitizeMetadata(entry.metadata),
      });
    if (error) throw error;
    return true;
  } catch (error) {
    logError("audit.write_failed", error, { action: entry.action });
    return false;
  }
}
