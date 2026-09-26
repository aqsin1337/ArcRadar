import { SearchX } from "lucide-react";
import Link from "next/link";
import { buttonClasses } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";

export default function NotFound() {
  return (
    <main id="main" className="flex min-h-dvh items-center justify-center px-4">
      <EmptyState
        icon={SearchX}
        title="Page not found"
        description="The page you're looking for doesn't exist or has moved."
        detail="404"
        action={
          <Link href="/" className={buttonClasses()}>
            Back to ArcRadar
          </Link>
        }
      />
    </main>
  );
}
