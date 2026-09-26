"use client";

import Link from "next/link";
import { useEffect } from "react";
import { Button, buttonClasses } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";

/** Error boundary for pages inside the app shell: the sidebar and header stay usable. */
export default function AppError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  useEffect(() => {
    // The browser console only; the server log has the full error, matched by `digest`.
    console.error(error);
  }, [error]);

  return (
    <ErrorState
      title="Something went wrong"
      description="This page failed to load. You can try again, or go back to the overview."
      detail={error.digest ? `Reference: ${error.digest}` : undefined}
      action={
        <>
          <Button onClick={() => retry()}>Try again</Button>
          <Link href="/dashboard" className={buttonClasses({ variant: "secondary" })}>
            Go to overview
          </Link>
        </>
      }
    />
  );
}
