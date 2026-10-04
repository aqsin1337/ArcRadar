import { SearchX } from "lucide-react";
import Link from "next/link";
import { buttonClasses } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";

/** "Not found" for pages inside the app shell, so the sidebar and header stay in place. */
export default function AppNotFound() {
  return (
    <EmptyState
      icon={SearchX}
      title="Not found"
      description="This record does not exist, or it was deleted."
      action={
        <Link href="/dashboard" className={buttonClasses({ variant: "secondary" })}>
          Go to the overview
        </Link>
      }
    />
  );
}
