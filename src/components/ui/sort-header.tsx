import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import Link from "next/link";
import { Th } from "@/components/ui/table";

/**
 * A sortable table header: a link, so sorting is a normal navigation (it works without JavaScript
 * and the URL records it). A second click reverses the order. `hrefFor` builds the list URL.
 */
export function SortHeader({
  label,
  field,
  sort,
  order,
  hrefFor,
  className,
}: {
  label: string;
  field: string;
  /** The column the list is sorted by now, and the direction. */
  sort: string;
  order: string;
  hrefFor: (field: string, order: "asc" | "desc") => string;
  className?: string;
}) {
  const current = sort === field;
  const nextOrder = current && order === "asc" ? "desc" : "asc";
  const Icon = !current ? ChevronsUpDown : order === "asc" ? ArrowUp : ArrowDown;
  return (
    <Th
      className={className}
      aria-sort={current ? (order === "asc" ? "ascending" : "descending") : undefined}
    >
      <Link
        href={hrefFor(field, nextOrder)}
        className="-mx-1 inline-flex items-center gap-1 rounded px-1 hover:text-foreground"
      >
        {label}
        <Icon aria-hidden className={current ? "size-3.5" : "size-3.5 opacity-50"} />
        <span className="sr-only">, sort {nextOrder === "asc" ? "ascending" : "descending"}</span>
      </Link>
    </Th>
  );
}
