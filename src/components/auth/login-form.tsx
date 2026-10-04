"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { PasswordField } from "@/components/ui/password-field";
import { apiFetch } from "@/lib/api/client";
import type { SessionInfo } from "@/lib/auth/context";
import type { DemoLogins } from "@/lib/demo-accounts";
import { safeRedirectPath } from "@/lib/auth/redirect";
import { loginSchema } from "@/lib/validation/auth";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";

export type LoginNotice = "invalid_link" | "callback_failed" | null;

const NOTICES: Record<Exclude<LoginNotice, null>, string> = {
  invalid_link: "That link is invalid or has expired. Sign in, or request a new link.",
  callback_failed: "We couldn't complete the sign-in from that link. Try signing in again.",
};

export function LoginForm({
  next,
  notice,
  demo,
}: {
  next: string;
  notice: LoginNotice;
  /** Seeded local accounts to offer as one-click fill; null hides the panel. Supplied by the server. */
  demo: DemoLogins | null;
}) {
  const router = useRouter();
  const form = useRef<HTMLFormElement>(null);
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  function fillDemo(email: string) {
    const elements = form.current?.elements;
    const emailInput = elements?.namedItem("email") as HTMLInputElement | null;
    const passwordInput = elements?.namedItem("password") as HTMLInputElement | null;
    if (emailInput) emailInput.value = email;
    if (passwordInput) passwordInput.value = demo?.password ?? "";
    setErrors({});
    setFormError(null);
    passwordInput?.focus();
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;

    const data = new FormData(event.currentTarget);
    const parsed = loginSchema.safeParse({
      email: formText(data, "email"),
      password: formText(data, "password"),
    });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      setFormError(null);
      return;
    }

    setErrors({});
    setFormError(null);
    setPending(true);
    const result = await apiFetch<SessionInfo>("/api/auth/login", { body: parsed.data });
    if (!result.ok) {
      setPending(false);
      setFormError(result.message);
      return;
    }
    // Stay in the pending state until the navigation completes, so the form cannot be sent twice.
    router.replace(safeRedirectPath(next, "/dashboard"));
    router.refresh();
  }

  return (
    <form ref={form} onSubmit={onSubmit} noValidate className="space-y-4">
      <div className="space-y-3 empty:hidden">
        {notice && <Alert tone="warning">{NOTICES[notice]}</Alert>}
        {formError && <Alert tone="error">{formError}</Alert>}
      </div>

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
      <PasswordField
        id="password"
        name="password"
        label="Password"
        autoComplete="current-password"
        required
        error={errors.password}
      />

      <div className="flex justify-end">
        <Link href="/forgot-password" className="text-sm font-medium text-primary hover:underline">
          Forgot password?
        </Link>
      </div>

      <Button type="submit" size="lg" className="w-full" loading={pending}>
        {pending ? "Signing in…" : "Sign in"}
      </Button>

      {demo && (
        <div className="space-y-2 rounded-lg border border-dashed border-tone-violet-border bg-tone-violet-bg/40 p-3">
          <p className="text-xs text-tone-violet-fg">
            <span className="font-semibold">Local demo accounts.</span> Fill the form with a seeded
            user (demo data, local database only).
          </p>
          <div className="flex flex-wrap gap-2">
            {demo.accounts.map((account) => (
              <Button
                key={account.email}
                variant="secondary"
                size="sm"
                onClick={() => fillDemo(account.email)}
              >
                {account.label}
              </Button>
            ))}
          </div>
        </div>
      )}
    </form>
  );
}
