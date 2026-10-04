import type { ReactNode } from "react";
import { formatDateTime } from "@/lib/format";

/** One label/value line of a `<dl>` (wrap several in `<dl className="divide-y divide-border">`). */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 py-2 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-right font-medium break-words">{children}</dd>
    </div>
  );
}

/** A UTC timestamp as text, with the machine-readable value for assistive technology and a tooltip. */
export function TimeText({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={iso}>
      {formatDateTime(iso)}
    </time>
  );
}
