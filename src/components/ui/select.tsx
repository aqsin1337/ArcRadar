import { ChevronDown } from "lucide-react";
import type { ReactNode, SelectHTMLAttributes } from "react";
import { cn } from "@/lib/cn";
import { FieldFrame } from "./input";

type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & { invalid?: boolean };

/** A native <select> (keyboard, mobile pickers and screen readers work as users expect) with the app's look. */
export function Select({ invalid = false, className, children, ...props }: SelectProps) {
  return (
    <div className="relative">
      <select
        aria-invalid={invalid || undefined}
        className={cn(
          "h-10 w-full appearance-none rounded-lg border bg-surface pr-9 pl-3 text-sm text-foreground transition-colors",
          "disabled:cursor-not-allowed disabled:opacity-60",
          "focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0",
          invalid ? "border-tone-red-fg" : "border-input-border",
          className,
        )}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden
        className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted"
      />
    </div>
  );
}

export type SelectOption = { value: string; label: string };

type SelectFieldProps = Omit<SelectProps, "id"> & {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
  options: readonly SelectOption[];
  /** Adds a first option with an empty value (for optional filters), for example "Any type". */
  placeholder?: string;
};

/** A labelled select with optional hint and error. */
export function SelectField({
  id,
  label,
  hint,
  error,
  required,
  options,
  placeholder,
  ...selectProps
}: SelectFieldProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error} required={required}>
      {(aria) => (
        <Select id={id} required={required} {...aria} {...selectProps}>
          {placeholder !== undefined && <option value="">{placeholder}</option>}
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
      )}
    </FieldFrame>
  );
}
