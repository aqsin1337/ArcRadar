import { redirect } from "next/navigation";
import { SessionProvider } from "@/components/session-provider";
import { AppShell } from "@/components/shell/app-shell";
import { AccountDisabledScreen, ServiceUnavailableScreen } from "@/components/shell/screens";
import { toSessionInfo } from "@/lib/auth/context";
import { getPageAuth } from "@/lib/auth/session";

/**
 * Everything in this group needs a signed-in, active user. This is the real page guard: it verifies
 * the session with the auth server and loads the profile. (proxy.ts only redirects visitors with no
 * session cookie at all, as an optimistic shortcut.)
 */
export default async function AppLayout({ children }: LayoutProps<"/">) {
  const result = await getPageAuth();

  if (result.status === "signed_out") redirect("/login");
  if (result.status === "disabled") return <AccountDisabledScreen />;
  if (result.status === "unavailable") return <ServiceUnavailableScreen />;

  const session = toSessionInfo(result.auth);
  return (
    <SessionProvider session={session}>
      <AppShell session={session}>{children}</AppShell>
    </SessionProvider>
  );
}
