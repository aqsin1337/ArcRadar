"use client";

import { Printer } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Opens the browser's print dialog; the app shell is hidden in print (see globals.css / app-shell). */
export function PrintButton() {
  return (
    <Button variant="secondary" onClick={() => window.print()} className="print:hidden">
      <Printer aria-hidden className="size-4" />
      Print or save as PDF
    </Button>
  );
}
