import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import type { AlertTechnique } from "@/lib/alerts/types";

/**
 * The ATT&CK techniques a sensor tagged an alert with. One the workspace knows links to its page; one
 * it does not (the workspace holds a subset of ATT&CK) is shown as plain text, never as a dead link.
 */
export function TechniqueChips({ items }: { items: AlertTechnique[] }) {
  return (
    <ul className="flex flex-wrap justify-end gap-1.5" aria-label="ATT&CK techniques">
      {items.map((technique) => (
        <li key={technique.id}>
          {technique.name ? (
            <Link
              href={`/mitre/${technique.id}`}
              title={technique.name}
              className="inline-flex rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs font-medium text-primary hover:underline"
            >
              {technique.id}
            </Link>
          ) : (
            <Badge tone="slate" className="font-mono">
              {technique.id}
            </Badge>
          )}
        </li>
      ))}
    </ul>
  );
}
