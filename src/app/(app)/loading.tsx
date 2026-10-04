import { Skeleton } from "@/components/ui/skeleton";

/** Shown while a page in the app is rendering on the server. Mirrors the PageHeader + card grid. */
export default function AppLoading() {
  return (
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading…</span>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-4 w-full max-w-md" />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-64 lg:col-span-2" />
        <Skeleton className="h-64" />
        <Skeleton className="h-36 lg:col-span-3" />
      </div>
    </div>
  );
}
