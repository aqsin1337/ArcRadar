import { Skeleton } from "@/components/ui/skeleton";

/** Placeholder while one vulnerability loads. */
export default function VulnerabilityLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading vulnerability…</span>
      <Skeleton className="mb-4 h-4 w-40" />
      <div className="mb-6 space-y-3">
        <Skeleton className="h-8 w-64" />
        <div className="flex gap-2">
          <Skeleton className="h-6 w-20" />
          <Skeleton className="h-6 w-24" />
          <Skeleton className="h-6 w-28" />
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Skeleton className="h-40 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-44 w-full rounded-xl" />
          <Skeleton className="h-36 w-full rounded-xl" />
        </div>
      </div>
    </div>
  );
}
