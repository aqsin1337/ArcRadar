import { Skeleton } from "@/components/ui/skeleton";

/** Placeholder while the alert list (or an alert) loads: header, statistics tiles, filter bar, table rows. */
export default function AlertsLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading alerts…</span>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-4 w-full max-w-lg" />
      </div>
      <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {Array.from({ length: 7 }, (_, index) => (
          <Skeleton key={index} className="h-20" />
        ))}
      </div>
      <Skeleton className="mb-3 h-10 w-full" />
      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {Array.from({ length: 5 }, (_, index) => (
          <Skeleton key={index} className="h-14" />
        ))}
      </div>
      <div className="space-y-2 rounded-xl border border-border p-3">
        {Array.from({ length: 8 }, (_, index) => (
          <Skeleton key={index} className="h-12 w-full" />
        ))}
      </div>
    </div>
  );
}
