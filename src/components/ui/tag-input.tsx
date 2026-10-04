"use client";

import { X } from "lucide-react";
import { useId, useState, type KeyboardEvent } from "react";
import { FieldFrame } from "./input";
import { cn } from "@/lib/cn";
import { MAX_INDICATOR_TAGS } from "@/lib/indicators/constants";
import { tagNameSchema } from "@/lib/indicators/schema";

type TagInputProps = {
  id: string;
  label: string;
  value: string[];
  onChange: (tags: string[]) => void;
  /** Existing tag names, offered as suggestions through a native datalist. */
  suggestions?: string[];
  error?: string;
  max?: number;
};

/**
 * Chips plus a text box. Enter or comma adds the tag being typed, Backspace on an empty box removes
 * the last chip, and each chip has its own labelled remove button. Names are validated with the same
 * schema the server uses; duplicates (ignoring case) are ignored.
 */
export function TagInput({
  id,
  label,
  value,
  onChange,
  suggestions = [],
  error,
  max = MAX_INDICATOR_TAGS,
}: TagInputProps) {
  const [draft, setDraft] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const listId = useId();

  function add(raw: string) {
    const text = raw.trim();
    if (!text) return true;
    const parsed = tagNameSchema.safeParse(text);
    if (!parsed.success) {
      setProblem(parsed.error.issues[0].message);
      return false;
    }
    if (value.some((tag) => tag.toLowerCase() === parsed.data.toLowerCase())) {
      setProblem(null);
      return true;
    }
    if (value.length >= max) {
      setProblem(`An indicator can have at most ${max} tags.`);
      return false;
    }
    setProblem(null);
    onChange([...value, parsed.data]);
    return true;
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      if (add(draft)) setDraft("");
    } else if (event.key === "Backspace" && draft === "" && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  }

  return (
    <FieldFrame
      id={id}
      label={label}
      error={error ?? problem ?? undefined}
      hint={`Press Enter to add a tag. ${value.length} of ${max} used.`}
    >
      {(aria) => (
        <div
          className={cn(
            "flex min-h-10 flex-wrap items-center gap-1.5 rounded-lg border bg-surface px-2 py-1.5",
            "focus-within:border-ring focus-within:outline-2 focus-within:outline-ring",
            aria.invalid ? "border-tone-red-fg" : "border-input-border",
          )}
        >
          {value.map((tag) => (
            <span
              key={tag}
              className="inline-flex items-center gap-1 rounded-md border border-tone-slate-border bg-tone-slate-bg py-0.5 pr-0.5 pl-2 text-xs font-medium text-tone-slate-fg"
            >
              {tag}
              <button
                type="button"
                onClick={() => onChange(value.filter((other) => other !== tag))}
                aria-label={`Remove tag ${tag}`}
                className="flex size-5 items-center justify-center rounded hover:bg-surface-2"
              >
                <X aria-hidden className="size-3" />
              </button>
            </span>
          ))}
          <input
            id={id}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              if (problem) setProblem(null);
            }}
            onKeyDown={onKeyDown}
            // Leaving the box with text in it adds the tag, so nothing typed is silently lost.
            onBlur={() => {
              if (draft.trim() && add(draft)) setDraft("");
            }}
            list={listId}
            maxLength={60}
            autoComplete="off"
            aria-describedby={aria["aria-describedby"]}
            aria-invalid={aria.invalid || undefined}
            className="h-7 min-w-32 flex-1 bg-transparent px-1 text-sm outline-none placeholder:text-muted"
            placeholder={value.length === 0 ? "c2, phishing, ransomware…" : ""}
          />
          <datalist id={listId}>
            {suggestions
              .filter((name) => !value.some((tag) => tag.toLowerCase() === name.toLowerCase()))
              .map((name) => (
                <option key={name} value={name} />
              ))}
          </datalist>
        </div>
      )}
    </FieldFrame>
  );
}
