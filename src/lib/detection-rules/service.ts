import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { DETECTION_RULE_ID_MAX, DETECTION_RULE_ID_MIN } from "./constants";
import {
  deleteDetectionRuleRow,
  findDetectionRules,
  insertDetectionRule,
  updateDetectionRuleRow,
} from "./repository";
import type { CreateDetectionRuleInput, UpdateDetectionRuleInput } from "./schema";
import type { DetectionRule } from "./types";

type RequestLike = { headers: Headers };

/** A malformed id (not an integer, or outside the reserved range) is simply "not found". */
export const isRuleId = (id: number) =>
  Number.isInteger(id) && id >= DETECTION_RULE_ID_MIN && id <= DETECTION_RULE_ID_MAX;

export const listDetectionRules = (supabase: AuthClient): Promise<DetectionRule[]> =>
  findDetectionRules(supabase);

export async function createDetectionRule(
  auth: AuthContext,
  input: CreateDetectionRuleInput,
  request: RequestLike,
): Promise<DetectionRule> {
  const row = await insertDetectionRule(auth.supabase, input);
  await writeAuditLog(
    {
      action: "detection_rule.created",
      userId: auth.user.id,
      entityType: "detection_rule",
      entityId: String(row.id),
      metadata: { id: row.id, name: row.name },
    },
    request,
  );
  return row;
}

export async function updateDetectionRule(
  auth: AuthContext,
  id: number,
  input: UpdateDetectionRuleInput,
  request: RequestLike,
): Promise<DetectionRule> {
  if (!isRuleId(id)) throw apiErrors.notFound("Detection rule not found.");
  const row = await updateDetectionRuleRow(auth.supabase, id, input);
  if (!row) throw apiErrors.notFound("Detection rule not found.");
  await writeAuditLog(
    {
      action: "detection_rule.updated",
      userId: auth.user.id,
      entityType: "detection_rule",
      entityId: String(id),
      metadata: { name: row.name, fields: Object.keys(input) },
    },
    request,
  );
  return row;
}

export async function deleteDetectionRule(
  auth: AuthContext,
  id: number,
  request: RequestLike,
): Promise<void> {
  if (!isRuleId(id)) throw apiErrors.notFound("Detection rule not found.");
  const removed = await deleteDetectionRuleRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Detection rule not found.");
  await writeAuditLog(
    {
      action: "detection_rule.deleted",
      userId: auth.user.id,
      entityType: "detection_rule",
      entityId: String(id),
      metadata: { name: removed.name },
    },
    request,
  );
}
