import type { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

/**
 * Data table primitives. The wrapper scrolls horizontally on small screens instead of squeezing
 * columns, and is focusable so keyboard users can scroll it. Give it a `caption` or aria-label.
 */
export function Table({
  className,
  caption,
  children,
  ...props
}: HTMLAttributes<HTMLTableElement> & { caption: string }) {
  return (
    <div
      tabIndex={0}
      role="region"
      aria-label={caption}
      className="overflow-x-auto rounded-xl border border-border bg-surface"
    >
      <table className={cn("w-full border-collapse text-left text-sm", className)} {...props}>
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}

export function THead({ className, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn("border-b border-border bg-surface-2", className)} {...props} />;
}

export function TBody({ className, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn("divide-y divide-border", className)} {...props} />;
}

export function Tr({ className, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn("hover:bg-surface-2/60", className)} {...props} />;
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={cn(
        "px-3 py-2.5 text-xs font-semibold tracking-wide text-muted uppercase",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("px-3 py-3 align-middle", className)} {...props} />;
}
