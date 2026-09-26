"use client";

import { Eye, EyeOff } from "lucide-react";
import { useState, type InputHTMLAttributes, type ReactNode } from "react";
import { PASSWORD_RULES } from "@/lib/validation/auth";
import { cn } from "@/lib/cn";
import { FieldFrame, Input } from "./input";

type PasswordFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "type"> & {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
};

/** Password input with a show/hide toggle. The toggle is a real button, so it is keyboard reachable. */
export function PasswordField({
  id,
  label,
  hint,
  error,
  required,
  className,
  ...inputProps
}: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);

  return (
    <FieldFrame id={id} label={label} hint={hint} error={error} required={required}>
      {(aria) => (
        <div className="relative">
          <Input
            id={id}
            type={visible ? "text" : "password"}
            required={required}
            className={cn("pr-11", className)}
            {...aria}
            {...inputProps}
          />
          <button
            type="button"
            onClick={() => setVisible((value) => !value)}
            aria-label={visible ? "Hide password" : "Show password"}
            aria-pressed={visible}
            className="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-lg text-muted hover:text-foreground"
          >
            {visible ? (
              <EyeOff aria-hidden className="size-4" />
            ) : (
              <Eye aria-hidden className="size-4" />
            )}
          </button>
        </div>
      )}
    </FieldFrame>
  );
}

/** Live checklist of the password policy. Pass the current value; unmet rules stay muted. */
export function PasswordRules({ value }: { value: string }) {
  return (
    <ul aria-label="Password requirements" className="grid gap-1 text-xs">
      {PASSWORD_RULES.map((rule) => {
        const met = rule.test(value);
        return (
          <li
            key={rule.id}
            className={cn("flex items-center gap-2", met ? "text-tone-green-fg" : "text-muted")}
          >
            <span
              aria-hidden
              className={cn(
                "flex size-3.5 items-center justify-center rounded-full border text-[9px] leading-none",
                met ? "border-tone-green-border bg-tone-green-bg" : "border-input-border",
              )}
            >
              {met ? "✓" : ""}
            </span>
            {rule.label}
            <span className="sr-only">{met ? " (met)" : " (not met yet)"}</span>
          </li>
        );
      })}
    </ul>
  );
}
