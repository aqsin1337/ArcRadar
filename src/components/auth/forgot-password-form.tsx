"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { apiFetch } from "@/lib/api/client";
import { forgotPasswordSchema } from "@/lib/validation/auth";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";

export function ForgotPasswordForm() {
  const [pending, setPending] = useState(false);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;

    const parsed = forgotPasswordSchema.safeParse({
      email: formText(new FormData(event.currentTarget), "email"),
    });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      setFormError(null);
      return;
    }

    setErrors({});
    setFormError(null);
    setPending(true);
    const result = await apiFetch("/api/auth/forgot-password", { body: parsed.data });
    setPending(false);
    if (!result.ok) {
      setFormError(result.message);
      return;
    }
    setSentTo(parsed.data.email);
  }

  if (sentTo) {
    return (
      <div className="space-y-4">
        <Alert tone="success" title="Check your inbox">
          If an account exists for <strong className="font-semibold">{sentTo}</strong>, we&apos;ve
          sent a link to set a new password. It can take a minute to arrive.
        </Alert>
        <Link
          href="/login"
          className={buttonClasses({ variant: "secondary", size: "lg", className: "w-full" })}
        >
          Back to sign in
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {formError && <Alert tone="error">{formError}</Alert>}
      <TextField
        id="email"
        name="email"
        type="email"
        label="Email"
        autoComplete="username"
        inputMode="email"
        autoFocus
        required
        error={errors.email}
      />
      <Button type="submit" size="lg" className="w-full" loading={pending}>
        {pending ? "Sending…" : "Send reset link"}
      </Button>
    </form>
  );
}
