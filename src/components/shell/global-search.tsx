"use client";

import { CornerDownLeft, Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useCan } from "@/components/session-provider";
import { OriginBadge } from "@/components/ui/domain-badges";
import { Spinner } from "@/components/ui/spinner";
import { apiFetch } from "@/lib/api/client";
import { cn } from "@/lib/cn";
import { indicatorListHref } from "@/lib/indicators/url";
import type { SearchHit, SearchResults } from "@/lib/search/service";

const MIN_CHARS = 2;
const DELAY_MS = 250;

type Status = "idle" | "loading" | "done" | "error";

/**
 * Search box in the app header. Type to see matching records grouped by kind; arrow keys move
 * through the results, Enter opens one (or, with none selected, the full indicator list for the
 * text), Escape closes. "/" or Ctrl/Cmd+K focuses it from anywhere on the page. Built as an ARIA
 * combobox with a listbox, and every keystroke cancels the request it makes obsolete.
 */
export function GlobalSearch() {
  const router = useRouter();
  const canSearch = useCan("indicators:read");
  const listId = useId();
  const root = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<Status>("idle");
  const [results, setResults] = useState<SearchResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(-1);

  const text = query.trim();
  const ready = text.length >= MIN_CHARS;
  const hits = useMemo(() => results?.groups.flatMap((group) => group.hits) ?? [], [results]);
  // The last option always exists once there is text: "see every match in the list".
  const optionCount = ready ? hits.length + 1 : 0;
  const allOptionIndex = hits.length;

  useEffect(() => {
    if (!ready) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setStatus("loading");
      const result = await apiFetch<SearchResults>(
        `/api/search?q=${encodeURIComponent(text)}&limit=6`,
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      if (result.ok) {
        setResults(result.data);
        setError(null);
        setStatus("done");
        setActive(-1);
      } else {
        setError(result.message);
        setStatus("error");
      }
    }, DELAY_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [text, ready]);

  // "/" and Ctrl/Cmd+K focus the search from anywhere except a text field.
  useEffect(() => {
    function onKey(event: globalThis.KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const typing =
        target?.isContentEditable ||
        ["INPUT", "TEXTAREA", "SELECT"].includes(target?.tagName ?? "");
      const shortcut =
        (event.key === "/" && !typing) ||
        (event.key.toLowerCase() === "k" && (event.ctrlKey || event.metaKey));
      if (!shortcut) return;
      event.preventDefault();
      input.current?.focus();
      input.current?.select();
      setOpen(true);
    }
    function onPointerDown(event: PointerEvent) {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, []);

  if (!canSearch) return null;

  function close() {
    setOpen(false);
    setActive(-1);
  }

  function goTo(href: string) {
    close();
    input.current?.blur();
    router.push(href);
  }

  function goToList() {
    goTo(indicatorListHref({ q: text }));
  }

  function choose(index: number) {
    if (index >= 0 && index < hits.length) goTo(hits[index].href);
    else if (ready) goToList();
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (optionCount === 0) return;
      event.preventDefault();
      setOpen(true);
      const step = event.key === "ArrowDown" ? 1 : -1;
      // Positions are -1 (nothing highlighted) then 0..optionCount-1, wrapping around.
      const positions = optionCount + 1;
      setActive((current) => ((((current + 1 + step) % positions) + positions) % positions) - 1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(active);
    } else if (event.key === "Escape") {
      if (open) {
        event.preventDefault();
        close();
      } else {
        setQuery("");
      }
    } else if (event.key === "Tab") {
      close();
    }
  }

  const showPanel = open && ready;
  const optionId = (index: number) => `${listId}-option-${index}`;
  let flatIndex = -1;

  return (
    <div ref={root} className="relative w-full">
      <label htmlFor={`${listId}-input`} className="sr-only">
        Search ArcRadar
      </label>
      <Search
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"
      />
      <input
        ref={input}
        id={`${listId}-input`}
        type="search"
        role="combobox"
        aria-expanded={showPanel}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={showPanel && active >= 0 ? optionId(active) : undefined}
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
          setOpen(true);
          if (event.target.value.trim().length < MIN_CHARS) {
            setResults(null);
            setStatus("idle");
          }
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
        placeholder="Search…"
        autoComplete="off"
        spellCheck={false}
        maxLength={200}
        className="h-9 w-full rounded-lg border border-input-border bg-surface pr-9 pl-9 text-sm text-foreground placeholder:text-muted focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0"
      />
      <kbd
        aria-hidden
        className="pointer-events-none absolute top-1/2 right-2.5 hidden -translate-y-1/2 rounded border border-border px-1.5 py-px text-[10px] text-muted lg:block"
      >
        /
      </kbd>
      {status === "loading" && (
        <Spinner className="absolute top-1/2 right-2.5 -translate-y-1/2 text-muted lg:hidden" />
      )}

      <div role="status" aria-live="polite" className="sr-only">
        {ready && status === "done" && `${hits.length} results`}
        {status === "error" && "Search failed"}
      </div>

      {showPanel && (
        <div
          id={listId}
          role="listbox"
          aria-label="Search results"
          className="fixed inset-x-3 top-14 z-40 max-h-[70dvh] overflow-y-auto rounded-xl border border-border bg-surface p-1.5 shadow-2xl sm:absolute sm:inset-x-auto sm:top-full sm:left-0 sm:mt-1.5 sm:w-[28rem] sm:max-w-[calc(100vw-2rem)]"
        >
          {status === "error" && (
            <p role="alert" className="px-3 py-3 text-sm text-tone-red-fg">
              {error ?? "Search is unavailable right now."}
            </p>
          )}
          {(status === "idle" || status === "loading") && hits.length === 0 && (
            <p className="px-3 py-3 text-sm text-muted">Searching…</p>
          )}
          {status === "done" && hits.length === 0 && (
            <p className="px-3 py-3 text-sm text-muted">No matches for “{text}”.</p>
          )}

          {results?.groups.map((group) => (
            <div key={group.kind} role="group" aria-label={group.label} className="mb-1">
              <p className="px-3 pt-2 pb-1 text-[11px] font-semibold tracking-wider text-muted uppercase">
                {group.label}
                {group.total > group.hits.length && (
                  <span className="ml-1 font-normal normal-case">
                    ({group.hits.length} of {group.total})
                  </span>
                )}
              </p>
              {group.hits.map((hit: SearchHit) => {
                flatIndex += 1;
                const index = flatIndex;
                return (
                  <div
                    key={hit.id}
                    id={optionId(index)}
                    role="option"
                    aria-selected={active === index}
                    onPointerDown={(event) => event.preventDefault()}
                    onClick={() => goTo(hit.href)}
                    onMouseMove={() => active !== index && setActive(index)}
                    className={cn(
                      "flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2",
                      active === index ? "bg-surface-2" : "hover:bg-surface-2",
                    )}
                  >
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-sm font-medium break-words">{hit.title}</p>
                      <p className="text-xs text-muted">{hit.subtitle}</p>
                    </div>
                    <OriginBadge origin={hit.origin} />
                  </div>
                );
              })}
            </div>
          ))}

          <div
            id={optionId(allOptionIndex)}
            role="option"
            aria-selected={active === allOptionIndex}
            onPointerDown={(event) => event.preventDefault()}
            onClick={goToList}
            onMouseMove={() => active !== allOptionIndex && setActive(allOptionIndex)}
            className={cn(
              "flex cursor-pointer items-center gap-2 rounded-lg border-t border-border px-3 py-2 text-sm",
              active === allOptionIndex ? "bg-surface-2" : "hover:bg-surface-2",
            )}
          >
            <Search aria-hidden className="size-4 text-muted" />
            <span className="min-w-0 flex-1 truncate">
              Search indicators for “<span className="font-medium">{text}</span>”
            </span>
            <CornerDownLeft aria-hidden className="size-3.5 text-muted" />
          </div>
        </div>
      )}
    </div>
  );
}
