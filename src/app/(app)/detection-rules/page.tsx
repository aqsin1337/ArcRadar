import type { Metadata } from "next";
import { DetectionRulesManager } from "@/components/detection-rules/rules-manager";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { listDetectionRules } from "@/lib/detection-rules/service";
import { getPageAuthContext } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Detection rules" };

export default async function DetectionRulesPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("rules:manage")) return <AccessDenied />;

  const rules = await listDetectionRules(auth.supabase);

  return (
    <>
      <PageHeader
        title="Detection rules"
        description="Rules ArcRadar checks against every alert as it is created, whether it arrived from telemetry or was recorded by hand. A match can raise the alert's severity and is always traceable on the alert itself; nothing here changes what an alert already says beyond that."
      />
      <DetectionRulesManager rules={rules} canManage={auth.permissions.has("rules:manage")} />
    </>
  );
}
