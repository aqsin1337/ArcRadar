"use client";

import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { DEFAULT_THEME, THEME_COOKIE, parseTheme, type Theme } from "@/lib/theme";
import { Button } from "./ui/button";

// The server writes `data-theme` on <html> from the cookie, so the attribute is the source of truth.
// Watching it keeps every toggle on the page in sync and avoids a flash or a hydration mismatch.
function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

const getSnapshot = (): Theme => parseTheme(document.documentElement.dataset.theme);
const getServerSnapshot = (): Theme => DEFAULT_THEME;

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const next: Theme = theme === "dark" ? "light" : "dark";

  function toggle() {
    document.documentElement.dataset.theme = next;
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${THEME_COOKIE}=${next}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
  }

  const Icon = theme === "dark" ? Sun : Moon;
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="size-9 px-0"
    >
      <Icon aria-hidden className="size-[1.1rem]" />
    </Button>
  );
}
