"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button, buttonClasses } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { PasswordField, PasswordRules } from "@/components/ui/password-field";
import { apiFetch } from "@/lib/api/client";
import { signupSchema } from "@/lib/validation/auth";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";

export function SignupForm() {
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [password, setPassword] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;

    const data = new FormData(event.currentTarget);
    const displayName = formText(data, "display_name").trim();
    const confirm = formText(data, "confirm_password");
    const parsed = signupSchema.safeParse({
      email: formText(data, "email"),
      password: formText(data, "password"),
      ...(displayName ? { display_name: displayName } : {}),
    });

    const nextErrors = parsed.success ? {} : fieldErrorsFromZod(parsed.error);
    if (formText(data, "password") !== confirm) {
      nextErrors.confirm_password = "Passwords do not match.";
    }
    if (!parsed.success || nextErrors.confirm_password) {
      setErrors(nextErrors);
      setFormError(null);
      return;
    }

    setErrors({});
    setFormError(null);
    setPending(true);
    const result = await apiFetch("/api/auth/signup", { body: parsed.data });
    setPending(false);
    if (!result.ok) {
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    setDone(true);
  }

  if (done) {
    return (
      <div className="space-y-4">
        <Alert tone="success" title="Request received">
          If this email can be registered, the account has been created. It stays locked until an
          administrator approves it and gives it a role, so you cannot sign in yet. Depending on the
          project&apos;s settings you may also need to confirm your email address first.
        </Alert>
        <Link href="/login" className={buttonClasses({ size: "lg", className: "w-full" })}>
          Continue to sign in
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {formError && <Alert tone="error">{formError}</Alert>}

      <TextField
        id="display_name"
        name="display_name"
        label="Name"
        hint="Optional. Shown to your team."
        autoComplete="name"
        maxLength={100}
        error={errors.display_name}
      />
      <TextField
        id="email"
        name="email"
        type="email"
        label="Email"
        autoComplete="username"
        inputMode="email"
        required
        error={errors.email}
      />
      <div className="space-y-3">
        <PasswordField
          id="password"
          name="password"
          label="Password"
          autoComplete="new-password"
          required
          error={errors.password}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        <PasswordRules value={password} />
      </div>
      <PasswordField
        id="confirm_password"
        name="confirm_password"
        label="Confirm password"
        autoComplete="new-password"
        required
        error={errors.confirm_password}
      />

      <Button type="submit" size="lg" className="w-full" loading={pending}>
        {pending ? "Creating account…" : "Create account"}
      </Button>
    </form>
  );
}
