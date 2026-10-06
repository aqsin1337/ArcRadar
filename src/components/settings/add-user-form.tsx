"use client";

import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { TextField } from "@/components/ui/input";
import { PasswordField, PasswordRules } from "@/components/ui/password-field";
import { SelectField } from "@/components/ui/select";
import { apiFetch } from "@/lib/api/client";
import { createUserSchema } from "@/lib/users/schema";
import type { AdminUser } from "@/lib/users/types";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";
import { ROLE_NAMES, roleLabel } from "@/types/domain";

/** What each role is for, in the words the role menu shows. */
const ROLE_HINTS: Record<(typeof ROLE_NAMES)[number], string> = {
  admin: "Admin: everything, including accounts, rules and keys",
  soc_l2: "SOC L2: investigates, opens cases, writes indicators and reports",
  soc_l1: "SOC L1: triages alerts and escalates",
  viewer: "Viewer: reads only",
};

/**
 * An administrator makes an account for a teammate. It can be used at once (no confirmation mail,
 * no approval step): the administrator picks the role here and passes the password on.
 */
export function AddUserForm({
  onCreated,
  onCancel,
}: {
  onCreated: (user: AdminUser) => void;
  onCancel: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [password, setPassword] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;

    const data = new FormData(event.currentTarget);
    const parsed = createUserSchema.safeParse({
      email: formText(data, "new_email"),
      password: formText(data, "new_password"),
      display_name: formText(data, "new_display_name"),
      role_name: formText(data, "new_role"),
    });
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      setFormError(null);
      return;
    }

    setErrors({});
    setFormError(null);
    setPending(true);
    const result = await apiFetch<AdminUser>("/api/users", { body: parsed.data });
    setPending(false);
    if (!result.ok) {
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    onCreated(result.data);
  }

  return (
    <Card>
      <form onSubmit={onSubmit} noValidate aria-label="Add an account">
        <CardContent className="space-y-4">
          {formError && <Alert tone="error">{formError}</Alert>}
          <div className="grid gap-4 sm:grid-cols-2">
            <TextField
              id="new_display_name"
              name="new_display_name"
              label="Name"
              autoComplete="off"
              maxLength={100}
              required
              error={errors.display_name}
            />
            <TextField
              id="new_email"
              name="new_email"
              type="email"
              label="Email"
              hint="They sign in with this. No confirmation mail is sent."
              autoComplete="off"
              inputMode="email"
              required
              error={errors.email}
            />
            <SelectField
              id="new_role"
              name="new_role"
              label="Role"
              defaultValue="soc_l1"
              required
              error={errors.role_name}
              options={ROLE_NAMES.map((role) => ({ value: role, label: ROLE_HINTS[role] }))}
            />
            <div className="space-y-3">
              <PasswordField
                id="new_password"
                name="new_password"
                label="First password"
                hint="Pass it on yourself. They can change it on their Profile page."
                autoComplete="new-password"
                required
                error={errors.password}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <PasswordRules value={password} />
            </div>
          </div>
        </CardContent>
        <CardFooter className="justify-end">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
          <Button type="submit" loading={pending}>
            {pending ? "Creating…" : "Create account"}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

/** The line shown after an account is made, so the administrator knows it is ready to use. */
export function createdNotice(user: AdminUser): string {
  return `${user.email} can sign in now as ${roleLabel(user.role)}.`;
}
