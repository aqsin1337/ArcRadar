"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PasswordField, PasswordRules } from "@/components/ui/password-field";
import { apiFetch } from "@/lib/api/client";
import { updatePasswordSchema } from "@/lib/validation/auth";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";

/** Sets a new password for the current session (the recovery link signs the user in first). */
export function ResetPasswordForm() {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [password, setPassword] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;

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
    setDone(true);
  }

  if (done) {
    return (
      <div className="space-y-4">
        <Alert tone="success" title="Password updated">
          Your password has been changed and your other sessions were signed out.
        </Alert>
        <Button
          size="lg"
          className="w-full"
          onClick={() => {
            router.replace("/dashboard");
            router.refresh();
          }}
        >
          Continue to the dashboard
        </Button>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {formError && <Alert tone="error">{formError}</Alert>}
      <div className="space-y-3">
        <PasswordField
          id="password"
          name="password"
          label="New password"
          autoComplete="new-password"
          autoFocus
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
        label="Confirm new password"
        autoComplete="new-password"
        required
        error={errors.confirm_password}
      />
      <Button type="submit" size="lg" className="w-full" loading={pending}>
        {pending ? "Saving…" : "Set new password"}
      </Button>
    </form>
  );
}
