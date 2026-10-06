import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ApiKeysManager } from "@/components/settings/api-keys-manager";
import { ProviderKeysManager } from "@/components/settings/provider-keys-manager";
import { API_KEY_SCOPES, SCOPE_PERMISSIONS } from "@/lib/api-keys/constants";
import { listApiKeys } from "@/lib/api-keys/service";
import { getPageAuthContext } from "@/lib/auth/session";
import { listSecrets } from "@/lib/secrets/service";

export const metadata: Metadata = { title: "API keys" };

export default async function ApiKeysPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("api_keys:manage_own")) return <AccessDenied />;

  const keys = await listApiKeys(auth);
  const scopes = API_KEY_SCOPES.filter((scope) => auth.permissions.has(SCOPE_PERMISSIONS[scope]));
  const secrets = auth.permissions.has("integrations:manage") ? await listSecrets() : null;

  return (
    <>
      <PageHeader
        title="API keys"
        description="Keys other services use to reach ArcRadar, and the keys ArcRadar uses to reach threat-intelligence, AI and GitHub services."
      />
      {secrets && (
        <section aria-labelledby="provider-keys-heading" className="mb-10 space-y-4">
          <div>
            <h2 id="provider-keys-heading" className="text-lg font-semibold tracking-tight">
              Keys ArcRadar uses
            </h2>
            <p className="text-sm text-muted">
              Paste a provider key and it works straight away. It is encrypted when saved and never
              shown again.
            </p>
          </div>
          <ProviderKeysManager initial={secrets} />
        </section>
      )}
      <section aria-labelledby="ingest-keys-heading" className="space-y-4">
        <div>
          <h2 id="ingest-keys-heading" className="text-lg font-semibold tracking-tight">
            Keys that send data in
          </h2>
          <p className="text-sm text-muted">
            A Wazuh Manager, a Splunk server or another machine uses one of these to send data to
            ArcRadar. A key is shown once, when it is made; ArcRadar keeps only its hash.
          </p>
        </div>
        {scopes.length === 0 ? (
          <p className="text-sm text-muted">
            Your role cannot issue any kind of key. An administrator can make one that sends Wazuh
            alerts.
          </p>
        ) : (
          <ApiKeysManager keys={keys} scopes={scopes} now={new Date()} />
        )}
      </section>
    </>
  );
}
