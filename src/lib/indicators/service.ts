import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { buildPage, type Page } from "@/lib/api/pagination";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import {
  deleteIndicatorRow,
  findAllTags,
  findIndicatorDetail,
  findIndicators,
  findTagsByIndicator,
  insertIndicator,
  replaceIndicatorTags,
  updateIndicatorRow,
} from "./repository";
import {
  indicatorIdSchema,
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
