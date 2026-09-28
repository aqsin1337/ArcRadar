import { toApiError } from "./supabase-errors";

type PageProbe = { error: { code?: string; message: string } | null; count: number | null };

/**
 * One page of a list, or an empty page when the requested page is past the last row (a stale link, a
 * hand-typed page number): PostgREST answers that with an error (`PGRST103`), so the total is learned
 * with a one-row read instead of failing.
 */
export async function fetchPage<T>(
  page: () => PromiseLike<PageProbe & { data: T[] | null }>,
  probe: () => PromiseLike<PageProbe>,
): Promise<{ rows: T[]; total: number }> {
  const { data, error, count } = await page();
  if (error?.code === "PGRST103") {
    const first = await probe();
    if (first.error) throw toApiError(first.error);
    return { rows: [], total: first.count ?? 0 };
  }
  if (error) throw toApiError(error);
  return { rows: data ?? [], total: count ?? 0 };
}
