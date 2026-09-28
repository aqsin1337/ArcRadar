import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { UsersTable } from "@/components/settings/users-table";
import { getPageAuthContext } from "@/lib/auth/session";
import { listUsers } from "@/lib/users/service";

export const metadata: Metadata = { title: "Settings" };

export default async function SettingsPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("settings:manage")) return <AccessDenied />;

  const users = await listUsers();

  return (
    <>
      <PageHeader
        title="Settings"
        description="Workspace administration: who has an account, their role, and whether they can sign in."
      />
      <UsersTable users={users} selfId={auth.user.id} now={new Date()} />
    </>
  );
}
