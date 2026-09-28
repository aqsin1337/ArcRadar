import { Skeleton } from "@/components/ui/skeleton";

/** Placeholder while the telemetry overview loads. */
export default function TelemetryLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading telemetry…</span>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-4 w-full max-w-lg" />
      </div>
      <div className="mb-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 3 }, (_, index) => (
          <Skeleton key={index} className="h-40" />
        ))}
      </div>
      <Skeleton className="mb-3 h-6 w-24" />
      <div className="mb-8 space-y-2 rounded-xl border border-border p-3">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-10 w-full" />
        ))}
      </div>
      <div className="space-y-2 rounded-xl border border-border p-3">
        {Array.from({ length: 6 }, (_, index) => (
          <Skeleton key={index} className="h-12 w-full" />
        ))}
      </div>
    </div>
  );
}
