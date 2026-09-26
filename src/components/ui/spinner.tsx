import { LoaderCircle } from "lucide-react";
import { cn } from "@/lib/cn";

/** Decorative spinner. Pair it with text (or `aria-busy` on the parent) so screen readers get the state. */
export function Spinner({ className }: { className?: string }) {
  return <LoaderCircle aria-hidden className={cn("size-4 animate-spin", className)} />;
}
