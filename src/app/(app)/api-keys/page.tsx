import type { Metadata } from "next";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ApiKeysManager } from "@/components/settings/api-keys-manager";
import { API_KEY_SCOPES, SCOPE_PERMISSIONS } from "@/lib/api-keys/constants";
import { listApiKeys } from "@/lib/api-keys/service";
import { getPageAuthContext } from "@/lib/auth/session";

export const metadata: Metadata = { title: "API keys" };

export default async function ApiKeysPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("api_keys:manage_own")) return <AccessDenied />;

  const keys = await listApiKeys(auth);
  const scopes = API_KEY_SCOPES.filter((scope) => auth.permissions.has(SCOPE_PERMISSIONS[scope]));

  return (
    <>
      <PageHeader
        title="API keys"
        description="Keys a Wazuh Manager or another machine uses to send data to ArcRadar. A key is shown once, when it is made; ArcRadar keeps only its hash."
      />
      {scopes.length === 0 ? (
        <p className="text-sm text-muted">
          Your role cannot issue any kind of key. An administrator can make one that sends Wazuh
          alerts.
        </p>
      ) : (
        <ApiKeysManager keys={keys} scopes={scopes} now={new Date()} />
      )}
    </>
  );
}
