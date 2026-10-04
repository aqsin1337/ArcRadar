"use client";

import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PasswordField, PasswordRules } from "@/components/ui/password-field";
import { apiFetch } from "@/lib/api/client";
import { updatePasswordSchema } from "@/lib/validation/auth";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";

/** Changes the signed-in user's password; every other session is signed out afterwards. */
export function ChangePasswordForm() {
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [password, setPassword] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setDone(false);

    const data = new FormData(event.currentTarget);
    const parsed = updatePasswordSchema.safeParse({ password: formText(data, "password") });
    const nextErrors = parsed.success ? {} : fieldErrorsFromZod(parsed.error);
    if (formText(data, "password") !== formText(data, "confirm_password")) {
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
    const result = await apiFetch("/api/auth/update-password", { body: parsed.data });
    setPending(false);
    if (!result.ok) {
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    setPassword("");
    (event.target as HTMLFormElement).reset();
    setDone(true);
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4" aria-label="Change password">
      {formError && <Alert tone="error">{formError}</Alert>}
      {done && !formError && (
        <Alert tone="success">Password changed. Your other sessions were signed out.</Alert>
      )}
      <div className="space-y-3">
        <PasswordField
          id="password"
          name="password"
          label="New password"
          autoComplete="new-password"
          required
          error={errors.password}
          value={password}
          onChange={(event) => {
            setDone(false);
            setPassword(event.target.value);
          }}
        />
        <PasswordRules value={password} />
      </div>
      <PasswordField
        id="confirm_password"
        name="confirm_password"
        label="Confirm new password"
        autoComplete="new-password"
        required
        error={errors.confirm_password}
      />
      <Button type="submit" loading={pending}>
        Change password
      </Button>
    </form>
  );
}
