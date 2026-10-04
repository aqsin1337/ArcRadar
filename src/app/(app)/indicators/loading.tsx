import { Skeleton } from "@/components/ui/skeleton";

/** Placeholder while the indicator list (or an indicator) loads: header, filter bar, table rows. */
export default function IndicatorsLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading indicators…</span>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-full max-w-lg" />
      </div>
      <Skeleton className="mb-3 h-10 w-full" />
      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }, (_, index) => (
          <Skeleton key={index} className="h-14" />
        ))}
      </div>
      <div className="space-y-2 rounded-xl border border-border p-3">
        {Array.from({ length: 8 }, (_, index) => (
          <Skeleton key={index} className="h-11 w-full" />
        ))}
      </div>
    </div>
  );
}
