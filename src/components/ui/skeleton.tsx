import type { HTMLAttributes } from "react";
import { cn } from "@/lib/cn";

/** Placeholder block for content that is still loading. Size it with className (h-*, w-*). */
export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden
      className={cn("animate-pulse rounded-md bg-surface-2", className)}
      {...props}
    />
  );
}
