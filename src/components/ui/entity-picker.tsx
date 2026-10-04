"use client";

import { Search } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Spinner } from "@/components/ui/spinner";

const MIN_CHARS = 2;
const DELAY_MS = 250;

type Status = "idle" | "loading" | "done" | "error";

/**
 * A small search-and-pick control: type at least two characters, choose a result. The search itself
 * is the caller's (`search`, usually a call to a list endpoint), every keystroke cancels the request
 * it makes obsolete, and results are announced politely to assistive technology.
 */
export function EntityPicker<T extends { id: string }>({
  id,
  label,
  placeholder,
  search,
  renderItem,
  onPick,
  exclude = [],
  disabled = false,
}: {
  id: string;
  label: string;
  placeholder: string;
  search: (text: string, signal: AbortSignal) => Promise<T[] | null>;
  renderItem: (item: T) => ReactNode;
  onPick: (item: T) => void;
  /** Ids to leave out of the results (for example what is already attached). */
  exclude?: string[];
  disabled?: boolean;
}) {
  const [text, setText] = useState("");
  const [items, setItems] = useState<T[]>([]);
  const [status, setStatus] = useState<Status>("idle");

  const query = text.trim();
  const ready = query.length >= MIN_CHARS;

  useEffect(() => {
    if (!ready) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setStatus("loading");
      const found = await search(query, controller.signal);
      if (controller.signal.aborted) return;
      if (found === null) {
        setStatus("error");
        return;
      }
      setItems(found);
      setStatus("done");
    }, DELAY_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
    // `search` is created by the caller on every render; the query is what should trigger a search.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, ready]);

  const shown =
    ready && status === "done" ? items.filter((item) => !exclude.includes(item.id)) : [];

  return (
    <div className="space-y-2">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      <div className="relative">
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"
        />
        <input
          id={id}
          type="search"
          value={text}
          disabled={disabled}
          onChange={(event) => {
            setText(event.target.value);
            if (event.target.value.trim().length < MIN_CHARS) setStatus("idle");
          }}
          placeholder={placeholder}
          autoComplete="off"
          maxLength={200}
          className="h-10 w-full rounded-lg border border-input-border bg-surface pr-10 pl-9 text-sm text-foreground placeholder:text-muted focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0 disabled:opacity-60"
        />
        <span className="absolute top-1/2 right-3 -translate-y-1/2">
          {ready && status === "loading" && <Spinner className="text-muted" />}
        </span>
      </div>
      <div aria-live="polite">
        {ready && status === "error" && (
          <p className="text-sm text-tone-red-fg">The search is unavailable right now.</p>
        )}
        {ready && status === "done" && shown.length === 0 && (
          <p className="text-sm text-muted">No matches.</p>
        )}
        {shown.length > 0 && (
          <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
            {shown.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => {
                    onPick(item);
                    setText("");
                    setItems([]);
                    setStatus("idle");
                  }}
                  className="block w-full px-3 py-2 text-left text-sm hover:bg-surface-2 focus-visible:bg-surface-2 disabled:opacity-60"
                >
                  {renderItem(item)}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
