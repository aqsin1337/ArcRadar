import { z } from "zod";

export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

/** Query parameters shared by every list endpoint: `?page=1&page_size=25`. */
export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  page_size: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE),
});

export type PaginationQuery = z.output<typeof paginationQuerySchema>;

export type Page<T> = {
  items: T[];
  pagination: { page: number; page_size: number; total: number; total_pages: number };
};

/** Inclusive row range for Supabase's `.range(from, to)`. */
export function toRange({ page, page_size }: PaginationQuery) {
  const from = (page - 1) * page_size;
  return { from, to: from + page_size - 1 };
}

export function buildPage<T>(items: T[], total: number, query: PaginationQuery): Page<T> {
  return {
    items,
    pagination: {
      page: query.page,
      page_size: query.page_size,
      total,
      total_pages: Math.ceil(total / query.page_size),
    },
  };
}
