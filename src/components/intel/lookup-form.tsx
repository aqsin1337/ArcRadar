"use client";

import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { INTEL_KIND_LABELS, INTEL_PLACEHOLDERS, intelHref } from "@/lib/intel/constants";
import type { IntelKind } from "@/lib/intel/types";

/**
 * The value box of a lookup page. The address is the state (`?q=`), so a lookup can be shared and the
 * back button works; without JavaScript the form still submits as an ordinary GET.
 */
export function LookupForm({ kind, initialValue }: { kind: IntelKind; initialValue: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [value, setValue] = useState(initialValue);

  // Follow the address when it changes from outside (a sample link, the back button).
  const [syncedValue, setSyncedValue] = useState(initialValue);
  if (syncedValue !== initialValue) {
    setSyncedValue(initialValue);
    setValue(initialValue);
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    startTransition(() => router.push(intelHref(kind, trimmed)));
  }

  return (
    <form
      role="search"
      aria-label={`${INTEL_KIND_LABELS[kind]} lookup`}
      action={`/intelligence/${kind}`}
      method="get"
      onSubmit={onSubmit}
      className="flex flex-col gap-2 sm:flex-row"
    >
      <div className="relative flex-1">
        <label htmlFor="intel-value" className="sr-only">
          Value to look up
        </label>
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"
        />
        <input
          id="intel-value"
          name="q"
          type="text"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={INTEL_PLACEHOLDERS[kind]}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={2048}
          required
          className="h-11 w-full rounded-lg border border-input-border bg-surface pr-3 pl-9 font-mono text-sm text-foreground placeholder:font-sans placeholder:text-muted focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0"
        />
      </div>
      <Button type="submit" size="lg" loading={pending} className="sm:w-32">
        Look up
      </Button>
    </form>
  );
}
