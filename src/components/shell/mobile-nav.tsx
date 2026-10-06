"use client";

import { Menu, X } from "lucide-react";
import { usePathname } from "next/navigation";
import { useEffect, useRef } from "react";
import { SignOutButton } from "@/components/auth/sign-out-button";
import { Button } from "@/components/ui/button";
import { LogoLink } from "@/components/ui/logo";
import { SidebarNav } from "./sidebar-nav";

/**
 * Slide-over navigation for screens below `lg`. Built on the native <dialog> element, which
 * provides the focus trap, Escape to close, and inert background for free.
 */
export function MobileNav() {
  const dialog = useRef<HTMLDialogElement>(null);
  const pathname = usePathname();

  // Close after navigating to another page.
  useEffect(() => {
    dialog.current?.close();
  }, [pathname]);

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="size-9 px-0 lg:hidden"
        aria-label="Open navigation"
        aria-haspopup="dialog"
        onClick={() => dialog.current?.showModal()}
      >
        <Menu aria-hidden className="size-5" />
      </Button>

      <dialog
        ref={dialog}
        aria-label="Navigation"
        onClick={(event) => {
          // A click on the ::backdrop is reported with the dialog itself as the target.
          if (event.target === dialog.current) dialog.current?.close();
        }}
        className="fixed inset-y-0 left-0 m-0 h-dvh max-h-none w-72 max-w-[85vw] border-r border-border bg-surface p-0 text-foreground backdrop:bg-black/60"
      >
        <div className="flex h-full flex-col">
          <div className="flex h-14 shrink-0 items-center justify-between border-b border-border px-4">
            <LogoLink
              href="/dashboard"
              label="ArcRadar, go to Overview"
              onClick={() => dialog.current?.close()}
            />
            <Button
              variant="ghost"
              size="sm"
              className="size-9 px-0"
              aria-label="Close navigation"
              onClick={() => dialog.current?.close()}
            >
              <X aria-hidden className="size-5" />
            </Button>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
            <SidebarNav idPrefix="mobile-nav" />
          </div>
          <div className="shrink-0 border-t border-border p-3">
            <SignOutButton variant="secondary" showLabel />
          </div>
        </div>
      </dialog>
    </>
  );
}
