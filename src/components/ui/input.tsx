import type { InputHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

type InputProps = InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean };

export function Input({ invalid = false, className, ...props }: InputProps) {
  return (
    <input
      aria-invalid={invalid || undefined}
      className={cn(
        "h-10 w-full rounded-lg border bg-surface px-3 text-sm text-foreground transition-colors",
        "placeholder:text-muted disabled:cursor-not-allowed disabled:opacity-60",
        "focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0",
        invalid ? "border-tone-red-fg" : "border-input-border",
        className,
      )}
      {...props}
    />
  );
}

type FieldFrameProps = {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
  required?: boolean;
  children: (aria: { "aria-describedby"?: string; invalid: boolean }) => ReactNode;
};

/** Label, control, hint and error message wired together with the right ARIA attributes. */
export function FieldFrame({ id, label, hint, error, required, children }: FieldFrameProps) {
  const describedBy = [hint ? `${id}-hint` : null, error ? `${id}-error` : null]
    .filter(Boolean)
    .join(" ");

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
        {required && (
          <span aria-hidden className="text-muted">
            {" "}
            *
          </span>
        )}
      </label>
      {children({ "aria-describedby": describedBy || undefined, invalid: Boolean(error) })}
      {hint && (
        <p id={`${id}-hint`} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} role="alert" className="text-xs font-medium text-tone-red-fg">
          {error}
        </p>
      )}
    </div>
  );
}

type TextFieldProps = Omit<InputProps, "id"> & {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
};

/** A labelled text input with optional hint and error. */
export function TextField({ id, label, hint, error, required, ...inputProps }: TextFieldProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error} required={required}>
      {(aria) => <Input id={id} required={required} {...aria} {...inputProps} />}
    </FieldFrame>
  );
}
