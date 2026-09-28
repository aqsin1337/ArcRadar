import { Skeleton } from "@/components/ui/skeleton";

/** Placeholder while a lookup runs: header, the value box, and the result cards. */
export default function IntelligenceLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Looking up…</span>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-4 w-full max-w-lg" />
      </div>
      <Skeleton className="mb-6 h-11 w-full" />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Skeleton className="h-72 w-full rounded-xl" />
          <Skeleton className="h-32 w-full rounded-xl" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-32 w-full rounded-xl" />
        </div>
      </div>
    </div>
  );
}
