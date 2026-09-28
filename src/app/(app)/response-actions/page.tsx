import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ResponseActionsCatalog } from "@/components/response-actions/catalog";
import { getPageAuthContext } from "@/lib/auth/session";
import { listResponseActions } from "@/lib/response-actions/service";

export const metadata: Metadata = { title: "Response actions" };

export default async function ResponseActionsPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("alerts:read")) return <AccessDenied />;

  const actions = await listResponseActions(auth.supabase);

  return (
    <>
      <PageHeader
        title="Response actions"
        description="A small, reusable catalog of response actions. An analyst can recommend one on an alert, or an AI 'suggest response actions' analysis can seed one automatically. Governed, not automated: nothing here is ever executed by the app — every action is recommended, then acknowledged, completed or skipped by a person."
      />
      <ResponseActionsCatalog
        actions={actions}
        canWrite={auth.permissions.has("investigations:write")}
      />
    </>
  );
}
