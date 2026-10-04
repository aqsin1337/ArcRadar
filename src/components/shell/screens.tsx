import { Hourglass, ShieldX } from "lucide-react";
import type { ReactNode } from "react";
import { SignOutButton } from "@/components/auth/sign-out-button";
import { RefreshButton } from "@/components/refresh-button";
import { ErrorState } from "@/components/ui/states";

function FullPage({ children }: { children: ReactNode }) {
  return (
    <main id="main" className="flex min-h-dvh items-center justify-center px-4">
      {children}
    </main>
  );
}

/** Signed up and confirmed, but an administrator has not approved the account yet. */
export function AccountPendingScreen() {
  return (
    <FullPage>
      <ErrorState
        icon={Hourglass}
        title="Waiting for approval"
        description="Your account was created, but an administrator has to approve it and give it a role before you can use ArcRadar. Try again once you have been told it is approved."
        action={<SignOutButton variant="secondary" showLabel />}
      />
    </FullPage>
  );
}

/** Signed in with a valid session, but the profile is inactive or has no usable role. */
export function AccountDisabledScreen() {
  return (
    <FullPage>
      <ErrorState
        icon={ShieldX}
        title="This account has no access"
        description="It has been disabled, or it has not been given a role yet. Contact an administrator if you think this is a mistake."
        action={<SignOutButton variant="secondary" showLabel />}
      />
    </FullPage>
  );
}

/** The auth backend or database could not be reached, so the session could not be verified. */
export function ServiceUnavailableScreen() {
  return (
    <FullPage>
      <ErrorState
        title="ArcRadar can't reach its services"
        description="The sign-in service is temporarily unavailable, so your session could not be checked. This is usually brief."
        action={<RefreshButton />}
      />
    </FullPage>
  );
}
