import { SearchX, type LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import type { Page } from "@/lib/api/pagination";
import { buttonClasses } from "./button";
import { Pagination } from "./pagination";
import { EmptyState } from "./states";

type Props = {
  pagination: Page<unknown>["pagination"];
  /** How many rows this page has (0 with a positive total means the page is past the end). */
  count: number;
  /** Whether a search or filter is set. */
  filtered: boolean;
  /** "threat actor", "threat actors". */
  noun: [singular: string, plural: string];
  /** The list without search or filters. */
  listHref: string;
  hrefForPage: (page: number) => string;
  empty: { icon: LucideIcon; title: string; description: string; action?: ReactNode };
  /** The table for a page that has rows. */
  children: ReactNode;
};

/**
 * What sits under a list page's filters: the match count, the table with its pagination, or the right
 * empty state (nothing yet, nothing matches, past the last page).
 */
export function ListResults({
  pagination,
  count,
  filtered,
  noun,
  listHref,
  hrefForPage,
  empty,
  children,
}: Props) {
  const [singular, plural] = noun;
  const beyondEnd = count === 0 && pagination.total > 0;
  const total = pagination.total;

  return (
    <>
      <div aria-live="polite" className="text-sm text-muted">
        {filtered
          ? `${total} ${total === 1 ? `${singular} matches` : `${plural} match`}`
          : `${total} ${total === 1 ? singular : plural}`}
      </div>

      {beyondEnd ? (
        <EmptyState
          icon={SearchX}
          title="That page is past the end"
          description={`There are ${pagination.total_pages} pages of results.`}
          action={
            <Link href={hrefForPage(pagination.total_pages)} className={buttonClasses()}>
              Go to the last page
            </Link>
          }
        />
      ) : count === 0 ? (
        filtered ? (
          <EmptyState
            icon={SearchX}
            title={`No ${plural} match`}
            description="Try fewer words, a different spelling, or remove a filter."
            action={
              <Link href={listHref} className={buttonClasses({ variant: "secondary" })}>
                Clear search and filters
              </Link>
            }
          />
        ) : (
          <EmptyState {...empty} />
        )
      ) : (
        <>
          {children}
          <Pagination
            page={pagination.page}
            totalPages={pagination.total_pages}
            total={total}
            pageSize={pagination.page_size}
            noun={plural}
            hrefForPage={hrefForPage}
          />
        </>
      )}
    </>
  );
}
