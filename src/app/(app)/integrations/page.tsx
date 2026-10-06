import type { Metadata } from "next";
import Link from "next/link";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AiProviderPicker } from "@/components/settings/ai-provider-picker";
import { IntegrationsList } from "@/components/settings/integrations-list";
import { getAiAvailability } from "@/lib/ai/service";
import { getPageAuthContext } from "@/lib/auth/session";
import { getIntegrations } from "@/lib/integrations/service";

export const metadata: Metadata = { title: "Integrations" };

export default async function IntegrationsPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("integrations:read")) return <AccessDenied />;

  const integrations = await getIntegrations(auth.supabase);
  const canUseAi = auth.permissions.has("ai:use");
  const aiAvailability = canUseAi ? await getAiAvailability(auth.supabase) : null;

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Every provider ArcRadar can use. A live provider needs a server-side key (set outside the app) and, once configured, can be paused here without removing the key."
      />
      <IntegrationsList
        integrations={integrations}
        canManage={auth.permissions.has("integrations:manage")}
        now={new Date()}
      />
      {aiAvailability && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>AI provider</CardTitle>
          </CardHeader>
          <CardContent>
            <AiProviderPicker
              availability={aiAvailability}
              canManage={auth.permissions.has("ai:manage")}
            />
          </CardContent>
        </Card>
      )}
      <p className="mt-4 text-xs text-muted">
        Wazuh and Splunk are configured per API key rather than one shared secret — see{" "}
        <Link href="/api-keys" className="underline underline-offset-2">
          API keys
        </Link>
        . Its live status (receiving, quiet, never delivered) is on the{" "}
        <Link href="/telemetry" className="underline underline-offset-2">
          Telemetry
        </Link>{" "}
        page.
      </p>
    </>
  );
}
