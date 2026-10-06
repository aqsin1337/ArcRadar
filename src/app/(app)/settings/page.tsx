import type { Metadata } from "next";
import { Alert } from "@/components/ui/alert";
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
  const waiting = users.filter((user) => user.pending).length;

  return (
    <>
      <PageHeader
        title="Settings"
        description="Workspace administration: who has an account, their role, and whether they can sign in. Add an account for a teammate here, or approve one that signed up."
      />
      {waiting > 0 && (
        <Alert
          tone="warning"
          title={`${waiting} account${waiting === 1 ? "" : "s"} waiting for approval`}
        >
          Pick a role in the list, then press Approve. Until you do, the person cannot use ArcRadar.
        </Alert>
      )}
      <UsersTable users={users} selfId={auth.user.id} now={new Date()} />
    </>
  );
}
