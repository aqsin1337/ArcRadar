import type { IndicatorTag } from "@/lib/indicators/types";

/**
 * Read-only tags. The stored tag color (a validated hex value) is shown only as a small dot: the
 * text stays in the theme's colors, so contrast holds in both themes whatever color a tag has.
 */
export function TagChips({ tags, limit }: { tags: IndicatorTag[]; limit?: number }) {
  if (tags.length === 0) return <span className="text-muted">—</span>;
  const shown = limit ? tags.slice(0, limit) : tags;
  const hidden = tags.length - shown.length;

  return (
    <ul className="flex flex-wrap gap-1" aria-label="Tags">
      {shown.map((tag) => (
        <li
          key={tag.id}
          className="inline-flex items-center gap-1.5 rounded-md border border-tone-slate-border bg-tone-slate-bg px-2 py-0.5 text-xs font-medium whitespace-nowrap text-tone-slate-fg"
        >
          {tag.color && (
            <span
              aria-hidden
              className="size-1.5 rounded-full"
              style={{ backgroundColor: tag.color }}
            />
          )}
          {tag.name}
        </li>
      ))}
      {hidden > 0 && (
        <li
          className="px-1 text-xs text-muted"
          title={tags
            .slice(limit)
            .map((t) => t.name)
            .join(", ")}
        >
          +{hidden}
          <span className="sr-only"> more tags</span>
        </li>
      )}
    </ul>
  );
}
