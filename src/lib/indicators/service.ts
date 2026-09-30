import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import {
  deleteIndicatorRow,
  deleteRelationshipRow,
  findAllTags,
  findIndicatorDetail,
  findIndicatorIdentity,
  findIndicators,
  findTagsByIndicator,
  insertIndicator,
  insertRelationship,
  replaceIndicatorTags,
  updateIndicatorRow,
} from "./repository";
import {
  indicatorIdSchema,
  relationshipIdSchema,
  type AddRelationshipInput,
  type CreateIndicatorInput,
  type IndicatorListQuery,
  type UpdateIndicatorInput,
} from "./schema";
import type { Indicator } from "@/types/domain";
import type { IndicatorDetail, IndicatorListItem, IndicatorTag } from "./types";

type RequestLike = { headers: Headers };

/** Page-level check for ids taken from a URL: a malformed id is simply "not found". */
export function isIndicatorId(id: string): boolean {
  return indicatorIdSchema.safeParse(id).success;
}

export async function listIndicators(
  supabase: AuthClient,
  query: IndicatorListQuery,
): Promise<Page<IndicatorListItem>> {
  const { rows, total } = await findIndicators(supabase, query);
  const tags = await findTagsByIndicator(
    supabase,
    rows.map((row) => row.id),
  );
  return buildPage(
    rows.map((row) => ({ ...row, tags: tags.get(row.id) ?? [] })),
    total,
    query,
  );
}

export function listTagOptions(supabase: AuthClient): Promise<IndicatorTag[]> {
  return findAllTags(supabase);
}

export async function getIndicator(supabase: AuthClient, id: string): Promise<IndicatorDetail> {
  if (!isIndicatorId(id)) throw apiErrors.notFound("Indicator not found.");
  const detail = await findIndicatorDetail(supabase, id);
  if (!detail) throw apiErrors.notFound("Indicator not found.");
  return detail;
}

async function withTags(supabase: AuthClient, row: Indicator): Promise<IndicatorListItem> {
  const tags = await findTagsByIndicator(supabase, [row.id]);
  return { ...row, tags: tags.get(row.id) ?? [] };
}

/** Creates a local indicator. A duplicate (same type, case-insensitive value) is a 409 naming the existing one. */
export async function createIndicator(
  auth: AuthContext,
  input: CreateIndicatorInput,
  request: RequestLike,
): Promise<IndicatorListItem> {
  const { tags, ...columns } = input;
  const row = await insertIndicator(auth.supabase, columns);
  if (tags && tags.length > 0) await replaceIndicatorTags(auth.supabase, row.id, tags);

  await writeAuditLog(
    {
      action: "indicator.created",
      userId: auth.user.id,
      entityType: "indicator",
      entityId: row.id,
      metadata: { type: row.type, value: row.value, severity: row.severity, origin: row.origin },
    },
    request,
  );
  return withTags(auth.supabase, row);
}

export async function updateIndicator(
  auth: AuthContext,
  id: string,
  input: UpdateIndicatorInput,
  request: RequestLike,
): Promise<IndicatorListItem> {
  if (!isIndicatorId(id)) throw apiErrors.notFound("Indicator not found.");

  const { tags, ...patch } = input;
  const row = await updateIndicatorRow(auth.supabase, id, patch);
  if (!row) throw apiErrors.notFound("Indicator not found.");
  if (tags) await replaceIndicatorTags(auth.supabase, id, tags);

  await writeAuditLog(
    {
      action: "indicator.updated",
      userId: auth.user.id,
      entityType: "indicator",
      entityId: id,
      metadata: { type: row.type, value: row.value, fields: Object.keys(input) },
    },
    request,
  );
  return withTags(auth.supabase, row);
}

/** Relates this indicator (the source) to another one. The same pair and kind twice is a 409. */
export async function addRelationship(
  auth: AuthContext,
  id: string,
  input: AddRelationshipInput,
  request: RequestLike,
): Promise<IndicatorDetail> {
  if (!isIndicatorId(id)) throw apiErrors.notFound("Indicator not found.");
  const { supabase } = auth;
  if (input.target_id === id) {
    throw apiErrors.validation({
      issues: [{ path: "target_id", message: "An indicator cannot be related to itself." }],
    });
  }

  const [source, target] = await Promise.all([
    findIndicatorIdentity(supabase, id),
    findIndicatorIdentity(supabase, input.target_id),
  ]);
  if (!source) throw apiErrors.notFound("Indicator not found.");
  if (!target) {
    throw apiErrors.validation({
      issues: [{ path: "target_id", message: "That indicator does not exist." }],
    });
  }

  const row = await insertRelationship(supabase, id, target.id, input.relationship);
  await writeAuditLog(
    {
      action: "indicator.relationship_added",
      userId: auth.user.id,
      entityType: "indicator",
      entityId: id,
      metadata: {
        relationship_id: row.id,
        relationship: input.relationship,
        source: source.value,
        target: target.value,
      },
    },
    request,
  );
  return getIndicator(supabase, id);
}

/** Removes a relationship that involves this indicator. */
export async function removeRelationship(
  auth: AuthContext,
  id: string,
  relationshipId: string,
  request: RequestLike,
): Promise<void> {
  if (!isIndicatorId(id) || !relationshipIdSchema.safeParse(relationshipId).success) {
    throw apiErrors.notFound("Relationship not found.");
  }
  const removed = await deleteRelationshipRow(auth.supabase, id, relationshipId);
  if (!removed) throw apiErrors.notFound("Relationship not found.");

  await writeAuditLog(
    {
      action: "indicator.relationship_removed",
      userId: auth.user.id,
      entityType: "indicator",
      entityId: id,
      metadata: {
        relationship_id: removed.id,
        relationship: removed.relationship,
        source_id: removed.source_indicator_id,
        target_id: removed.target_indicator_id,
      },
    },
    request,
  );
}

export async function deleteIndicator(
  auth: AuthContext,
  id: string,
  request: RequestLike,
): Promise<void> {
  if (!isIndicatorId(id)) throw apiErrors.notFound("Indicator not found.");

  const removed = await deleteIndicatorRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Indicator not found.");

  await writeAuditLog(
    {
      action: "indicator.deleted",
      userId: auth.user.id,
      entityType: "indicator",
      entityId: id,
      metadata: { type: removed.type, value: removed.value, origin: removed.origin },
    },
    request,
  );
}
