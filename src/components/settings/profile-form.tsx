"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/ui/input";
import { apiFetch } from "@/lib/api/client";
import { updateProfileSchema } from "@/lib/validation/auth";

/** Display name and avatar URL: the two fields RLS lets a person change on their own profile. */
export function ProfileForm({
  displayName,
  avatarUrl,
}: {
  displayName: string | null;
  avatarUrl: string | null;
}) {
  const router = useRouter();
  const [values, setValues] = useState({
    display_name: displayName ?? "",
    avatar_url: avatarUrl ?? "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    setFormError(null);
    setSaved(false);

    const parsed = updateProfileSchema.safeParse(values);
    if (!parsed.success) {
      const fieldErrors: Record<string, string> = {};
      for (const issue of parsed.error.issues) fieldErrors[String(issue.path[0])] = issue.message;
      setErrors(fieldErrors);
      return;
    }
    setErrors({});
    setPending(true);
    const result = await apiFetch("/api/auth/me", { method: "PATCH", body: parsed.data });
    setPending(false);
    if (!result.ok) {
      setErrors(result.fieldErrors);
      setFormError(result.message);
      return;
    }
    setSaved(true);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4" aria-label="Edit profile">
      {formError && <Alert tone="error">{formError}</Alert>}
      {saved && !formError && <Alert tone="success">Saved.</Alert>}
      <TextField
        id="display_name"
        label="Display name"
        hint="Shown instead of your email. Leave blank to use your email."
        value={values.display_name}
        onChange={(event) => {
          setSaved(false);
          setValues((current) => ({ ...current, display_name: event.target.value }));
        }}
        maxLength={100}
        error={errors.display_name}
      />
      <TextField
        id="avatar_url"
        label="Avatar URL"
        hint="A link to an image. Leave blank for none."
        value={values.avatar_url}
        onChange={(event) => {
          setSaved(false);
          setValues((current) => ({ ...current, avatar_url: event.target.value }));
        }}
        maxLength={2048}
        error={errors.avatar_url}
      />
      <Button type="submit" loading={pending}>
        Save profile
      </Button>
    </form>
  );
}
