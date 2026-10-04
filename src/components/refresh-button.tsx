"use client";

import { RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { Button, type ButtonVariant } from "./ui/button";

/** Re-runs the server render of the current page (for "try again" after a temporary failure). */
export function RefreshButton({
  label = "Try again",
  variant = "primary",
}: {
  label?: string;
  variant?: ButtonVariant;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  return (
    <Button
      variant={variant}
      loading={pending}
      onClick={() => startTransition(() => router.refresh())}
    >
      {!pending && <RefreshCw aria-hidden className="size-4" />}
      {label}
    </Button>
  );
}
