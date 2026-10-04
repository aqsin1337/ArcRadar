import type { ReactNode, TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/cn";
import { FieldFrame } from "./input";

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & { invalid?: boolean };

export function Textarea({ invalid = false, className, ...props }: TextareaProps) {
  return (
    <textarea
      aria-invalid={invalid || undefined}
      className={cn(
        "min-h-24 w-full rounded-lg border bg-surface px-3 py-2 text-sm text-foreground transition-colors",
        "placeholder:text-muted disabled:cursor-not-allowed disabled:opacity-60",
        "focus-visible:border-ring focus-visible:outline-2 focus-visible:outline-offset-0",
        invalid ? "border-tone-red-fg" : "border-input-border",
        className,
      )}
      {...props}
    />
  );
}

type TextAreaFieldProps = Omit<TextareaProps, "id"> & {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
};

/** A labelled multi-line input with optional hint and error. */
export function TextAreaField({
  id,
  label,
  hint,
  error,
  required,
  ...textareaProps
}: TextAreaFieldProps) {
  return (
    <FieldFrame id={id} label={label} hint={hint} error={error} required={required}>
      {(aria) => <Textarea id={id} required={required} {...aria} {...textareaProps} />}
    </FieldFrame>
  );
}
