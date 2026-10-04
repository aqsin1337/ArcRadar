"use client";

import { GeistSans } from "geist/font/sans";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import "./globals.css";

/**
 * Last-resort boundary for errors in the root layout itself. It replaces the whole document, so it
 * brings its own <html>/<body>; the theme cookie is not available here, so it uses the default.
 */
export default function GlobalError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  return (
    <html lang="en" data-theme="dark" className={GeistSans.variable}>
      <body>
        <main className="flex min-h-dvh items-center justify-center px-4">
          <ErrorState
            title="ArcRadar hit a problem"
            description="The app could not be displayed. Try again; if it keeps happening, contact an administrator."
            detail={error.digest ? `Reference: ${error.digest}` : undefined}
            action={<Button onClick={() => retry()}>Try again</Button>}
          />
        </main>
      </body>
    </html>
  );
}
