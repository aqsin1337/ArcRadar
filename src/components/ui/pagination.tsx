import { ChevronLeft, ChevronRight } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/cn";
import { buttonClasses } from "./button";

type PaginationProps = {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  /** URL of another page of the same list; keeps the current filters and sort. */
  hrefForPage: (page: number) => string;
  /** What is being counted, for the summary ("indicators"). */
  noun: string;
};

/** Which page numbers to show: the first, the last, and a window around the current page. */
export function pageWindow(page: number, totalPages: number): (number | "gap")[] {
  const wanted = new Set([1, totalPages, page - 1, page, page + 1]);
  const pages = [...wanted]
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((a, b) => a - b);
  const result: (number | "gap")[] = [];
  pages.forEach((value, index) => {
    if (index > 0 && value - pages[index - 1] > 1) result.push("gap");
    result.push(value);
  });
  return result;
}

/** Server-rendered pager: plain links, so it works without JavaScript and with the back button. */
export function Pagination({
  page,
  totalPages,
  total,
  pageSize,
  hrefForPage,
  noun,
}: PaginationProps) {
  if (total === 0) return null;
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  const disabled = "pointer-events-none opacity-50";

  return (
    <nav aria-label="Pagination" className="mt-4 flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-muted" aria-live="polite">
        Showing {first}–{last} of {total} {noun}
      </p>
      {totalPages > 1 && (
        <ul className="flex items-center gap-1">
          <li>
            <Link
              href={hrefForPage(Math.max(1, page - 1))}
              aria-disabled={page <= 1}
              tabIndex={page <= 1 ? -1 : undefined}
              aria-label="Previous page"
              className={cn(
                buttonClasses({ variant: "secondary", size: "sm", className: "px-2" }),
                page <= 1 && disabled,
              )}
            >
              <ChevronLeft aria-hidden className="size-4" />
            </Link>
          </li>
          {pageWindow(page, totalPages).map((entry, index) =>
            entry === "gap" ? (
              <li key={`gap-${index}`} aria-hidden className="px-1 text-muted">
                …
              </li>
            ) : (
              <li key={entry} className="hidden sm:block">
                <Link
                  href={hrefForPage(entry)}
                  aria-label={`Page ${entry}`}
                  aria-current={entry === page ? "page" : undefined}
                  className={buttonClasses({
                    variant: entry === page ? "primary" : "ghost",
                    size: "sm",
                    className: "min-w-8 px-2",
                  })}
                >
                  {entry}
                </Link>
              </li>
            ),
          )}
          <li className="text-sm text-muted sm:hidden" aria-hidden>
            {page} / {totalPages}
          </li>
          <li>
            <Link
              href={hrefForPage(Math.min(totalPages, page + 1))}
              aria-disabled={page >= totalPages}
              tabIndex={page >= totalPages ? -1 : undefined}
              aria-label="Next page"
              className={cn(
                buttonClasses({ variant: "secondary", size: "sm", className: "px-2" }),
                page >= totalPages && disabled,
              )}
            >
              <ChevronRight aria-hidden className="size-4" />
            </Link>
          </li>
        </ul>
      )}
    </nav>
  );
}
