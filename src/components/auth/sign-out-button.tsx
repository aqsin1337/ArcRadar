"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { apiFetch } from "@/lib/api/client";
import { Button, type ButtonVariant } from "@/components/ui/button";

/** Ends the session through the API, then returns to the login page. */
export function SignOutButton({
  variant = "ghost",
  showLabel = false,
}: {
  variant?: ButtonVariant;
  showLabel?: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signOut() {
    setPending(true);
    setError(null);
    const result = await apiFetch("/api/auth/logout", { method: "POST" });
    if (!result.ok) {
      setPending(false);
      setError(result.message);
      return;
    }
    router.replace("/login");
    router.refresh();
  }

  return (
    <>
      <Button
        variant={variant}
        size="sm"
        loading={pending}
        onClick={signOut}
        aria-label={showLabel ? undefined : "Sign out"}
        title={showLabel ? undefined : "Sign out"}
        className={showLabel ? undefined : "size-9 px-0"}
      >
        {!pending && <LogOut aria-hidden className="size-4" />}
        {showLabel && "Sign out"}
      </Button>
      {error && (
        <span role="alert" className="text-xs text-tone-red-fg">
          {error}
        </span>
      )}
    </>
  );
}
