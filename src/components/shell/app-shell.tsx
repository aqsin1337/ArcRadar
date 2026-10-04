import Link from "next/link";
import type { ReactNode } from "react";
import { SignOutButton } from "@/components/auth/sign-out-button";
import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Logo } from "@/components/ui/logo";
import type { SessionInfo } from "@/lib/auth/context";
import { roleLabel } from "@/types/domain";
import { GlobalSearch } from "./global-search";
import { MobileNav } from "./mobile-nav";
import { SidebarNav } from "./sidebar-nav";

function initials(name: string): string {
  const parts = name
    .trim()
    .split(/[\s@._-]+/)
    .filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

/**
 * The signed-in frame: fixed sidebar on large screens, a slide-over on small ones, and a top bar
 * with the theme toggle and the current user. Page content goes in <main id="main">.
 */
export function AppShell({ session, children }: { session: SessionInfo; children: ReactNode }) {
  const name = session.profile.display_name ?? session.user.email ?? "Signed in";

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[16rem_minmax(0,1fr)] print:block">
      <aside className="sticky top-0 hidden h-dvh flex-col border-r border-border bg-surface lg:flex print:hidden">
        <div className="flex h-14 shrink-0 items-center border-b border-border px-5">
          <Logo />
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
          <SidebarNav />
        </div>
      </aside>

      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/90 px-3 backdrop-blur sm:px-6 lg:px-8 print:hidden">
          <MobileNav />
          <div className="lg:hidden">
            <Logo className="[&>span:last-child]:hidden sm:[&>span:last-child]:inline" />
          </div>
          <div className="mx-1 min-w-0 flex-1 sm:mx-3 lg:max-w-xl">
            <GlobalSearch />
          </div>
          <div className="hidden flex-1 lg:block" />
          <ThemeToggle />
          <div className="mx-1 hidden h-6 w-px bg-border sm:block" aria-hidden />
          <Link
            href="/profile"
            className="flex min-w-0 items-center gap-2.5 rounded-lg p-1 -m-1 hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-ring"
          >
            <span
              aria-hidden
              className="flex size-8 shrink-0 items-center justify-center rounded-full bg-tone-brand-bg text-xs font-semibold text-tone-brand-fg"
            >
              {initials(name)}
            </span>
            <div className="hidden min-w-0 leading-tight sm:block">
              <p className="max-w-40 truncate text-sm font-medium" data-testid="user-name">
                {name}
              </p>
              <p className="max-w-40 truncate text-xs text-muted">{session.user.email}</p>
            </div>
            <span className="hidden sm:inline-flex">
              <Badge tone="brand" data-testid="user-role">
                {roleLabel(session.profile.role)}
              </Badge>
            </span>
          </Link>
          <SignOutButton />
        </header>

        <main
          id="main"
          tabIndex={-1}
          className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 outline-none sm:px-6 lg:px-8 lg:py-8 print:max-w-none print:p-0"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
