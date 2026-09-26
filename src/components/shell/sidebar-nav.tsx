"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useSession } from "@/components/session-provider";
import { cn } from "@/lib/cn";
import { isActivePath, visibleNavGroups } from "@/lib/nav";

/** The grouped navigation, filtered to what the signed-in user's role may see. */
export function SidebarNav({ idPrefix = "nav" }: { idPrefix?: string }) {
  const pathname = usePathname();
  const { permissions } = useSession();
  const groups = visibleNavGroups(permissions);

  return (
    <nav aria-label="Main" className="space-y-6">
      {groups.map((group, index) => {
        const headingId = `${idPrefix}-group-${index}`;
        return (
          <div
            key={group.label ?? "root"}
            role="group"
            aria-labelledby={group.label ? headingId : undefined}
          >
            {group.label && (
              <p
                id={headingId}
                className="mb-1.5 px-3 text-[11px] font-semibold tracking-wider text-muted uppercase"
              >
                {group.label}
              </p>
            )}
            <ul className="space-y-0.5">
              {group.items.map(({ label, href, icon: Icon, status }) => {
                const active = status === "live" && isActivePath(pathname, href);
                const base = "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm";

                if (status === "soon") {
                  return (
                    <li key={href}>
                      <span
                        aria-disabled="true"
                        className={cn(base, "cursor-default text-muted/80 select-none")}
                      >
                        <Icon aria-hidden className="size-4 shrink-0 opacity-70" />
                        <span className="min-w-0 flex-1 truncate">{label}</span>
                        <span className="rounded border border-border px-1.5 py-px text-[10px] font-medium tracking-wide text-muted uppercase">
                          Soon
                        </span>
                      </span>
                    </li>
                  );
                }

                return (
                  <li key={href}>
                    <Link
                      href={href}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        base,
                        "font-medium transition-colors",
                        active
                          ? "bg-tone-brand-bg text-tone-brand-fg"
                          : "text-foreground/85 hover:bg-surface-2 hover:text-foreground",
                      )}
                    >
                      <Icon aria-hidden className="size-4 shrink-0" />
                      <span className="min-w-0 flex-1 truncate">{label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}
