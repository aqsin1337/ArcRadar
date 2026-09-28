"use client";

import { useId, useState } from "react";
import { Input } from "./input";

export type PickerOption = { value: string; label: string; detail?: string | null };

type LinkPickerProps = {
  label: string;
  options: readonly PickerOption[];
  /** The selected values. */
  value: string[];
  onChange: (value: string[]) => void;
  hint?: string;
  error?: string;
  /** Shown when there is nothing to choose from. */
  emptyText: string;
};

const FILTER_FROM = 8;

/**
 * Pick any number of existing records from a list of checkboxes. Longer lists get a filter box;
 * choices hidden by the filter stay selected. Meant for small reference sets (a few hundred at most).
 */
export function LinkPicker({
  label,
  options,
  value,
  onChange,
  hint,
  error,
  emptyText,
}: LinkPickerProps) {
  const id = useId();
  const [filter, setFilter] = useState("");
  const selected = new Set(value);
  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? options.filter((option) =>
        `${option.label} ${option.detail ?? ""}`.toLowerCase().includes(needle),
      )
    : options;

  function toggle(optionValue: string, checked: boolean) {
    onChange(checked ? [...value, optionValue] : value.filter((item) => item !== optionValue));
  }

  return (
    <fieldset className="space-y-1.5" aria-describedby={hint ? `${id}-hint` : undefined}>
      <legend className="text-sm font-medium">
        {label} <span className="font-normal text-muted">({value.length} selected)</span>
      </legend>
      {options.length >= FILTER_FROM && (
        <Input
          type="search"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") event.preventDefault(); // Enter filters; it must not submit the form
          }}
          placeholder={`Filter ${label.toLowerCase()}`}
          aria-label={`Filter ${label.toLowerCase()}`}
          autoComplete="off"
          className="h-9"
        />
      )}
      <div
        className="max-h-52 overflow-auto rounded-lg border border-input-border bg-surface p-1"
        tabIndex={0}
        aria-label={`${label} choices`}
      >
        {options.length === 0 ? (
          <p className="px-2 py-1.5 text-sm text-muted">{emptyText}</p>
        ) : shown.length === 0 ? (
          <p className="px-2 py-1.5 text-sm text-muted">Nothing matches “{filter.trim()}”.</p>
        ) : (
          shown.map((option) => (
            <label
              key={option.value}
              className="flex cursor-pointer items-start gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-surface-2"
            >
              <input
                type="checkbox"
                checked={selected.has(option.value)}
                onChange={(event) => toggle(option.value, event.target.checked)}
                className="mt-0.5 size-4 shrink-0 accent-primary"
              />
              <span className="min-w-0 [overflow-wrap:anywhere]">
                {option.label}
                {option.detail && <span className="text-muted"> · {option.detail}</span>}
              </span>
            </label>
          ))
        )}
      </div>
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs font-medium text-tone-red-fg">
          {error}
        </p>
      )}
    </fieldset>
  );
}
