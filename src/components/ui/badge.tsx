import type { HTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export type Tone = "slate" | "brand" | "blue" | "green" | "amber" | "orange" | "red" | "violet";

// Full class names on purpose: Tailwind only generates classes it can find as literal strings.
const TONES: Record<Tone, string> = {
  slate: "bg-tone-slate-bg text-tone-slate-fg border-tone-slate-border",
  brand: "bg-tone-brand-bg text-tone-brand-fg border-tone-brand-border",
  blue: "bg-tone-blue-bg text-tone-blue-fg border-tone-blue-border",
  green: "bg-tone-green-bg text-tone-green-fg border-tone-green-border",
  amber: "bg-tone-amber-bg text-tone-amber-fg border-tone-amber-border",
  orange: "bg-tone-orange-bg text-tone-orange-fg border-tone-orange-border",
  red: "bg-tone-red-bg text-tone-red-fg border-tone-red-border",
  violet: "bg-tone-violet-bg text-tone-violet-fg border-tone-violet-border",
};

export function toneClasses(tone: Tone) {
  return TONES[tone];
}

type BadgeProps = HTMLAttributes<HTMLSpanElement> & {
  tone?: Tone;
  /** Adds a filled dot before the text. The text always carries the meaning, never color alone. */
  dot?: boolean;
  /** Dashed border, used for demo data so it never looks like a live record. */
  dashed?: boolean;
};

export function Badge({
  tone = "slate",
  dot = false,
  dashed = false,
  className,
  children,
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        dashed && "border-dashed",
        TONES[tone],
        className,
      )}
      {...props}
    >
      {dot && <span aria-hidden className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}
