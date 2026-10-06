import Link from "next/link";
import { cn } from "@/lib/cn";

/** The ArcRadar mark: concentric arcs with a sweep line, drawn in the current text color. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden
      className={cn("size-8", className)}
    >
      <circle cx="16" cy="16" r="13" opacity="0.4" />
      <path d="M16 6.5a9.5 9.5 0 0 1 9.5 9.5" />
      <path d="M16 11.5a4.5 4.5 0 0 1 4.5 4.5" />
      <path d="M16 16 25 7" />
      <circle cx="16" cy="16" r="1.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <LogoMark className="text-primary" />
      <span className="text-lg font-semibold tracking-tight">ArcRadar</span>
    </span>
  );
}

/**
 * The logo as the way home: Overview for someone inside the app, the landing page for a signed-out
 * visitor. `label` says where it goes, since the visible text is only the name.
 */
export function LogoLink({
  href,
  label,
  className,
  onClick,
}: {
  href: "/" | "/dashboard";
  label: string;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <Link
      href={href}
      aria-label={label}
      onClick={onClick}
      className="inline-flex rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-ring"
    >
      <Logo className={className} />
    </Link>
  );
}

/** Decorative radar rings for hero areas. Slow sweep; disabled by the reduced-motion rule. */
export function RadarBackdrop({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 400 400"
      fill="none"
      aria-hidden
      className={cn("pointer-events-none text-primary", className)}
    >
      <g stroke="currentColor" opacity="0.18">
        <circle cx="200" cy="200" r="60" />
        <circle cx="200" cy="200" r="110" />
        <circle cx="200" cy="200" r="160" />
        <circle cx="200" cy="200" r="195" />
        <path d="M200 5v390M5 200h390" strokeDasharray="2 6" />
      </g>
      {/* Classes, not a style attribute: the Content-Security-Policy refuses inline styles. */}
      <g className="origin-[200px_200px] animate-[arcradar-sweep_14s_linear_infinite]">
        <path d="M200 200 L200 5 A195 195 0 0 1 338 62 Z" fill="currentColor" opacity="0.08" />
        <path d="M200 200 L200 5" stroke="currentColor" opacity="0.5" />
      </g>
      <circle cx="268" cy="118" r="4" fill="currentColor" opacity="0.7" />
      <circle cx="140" cy="250" r="3" fill="currentColor" opacity="0.45" />
    </svg>
  );
}
