import type { Metadata } from "next";
import Link from "next/link";
import { DetectionRulesManager } from "@/components/detection-rules/rules-manager";
import { SiemRulesManager } from "@/components/detection-rules/siem-rules-manager";
import { WazuhRulesManager } from "@/components/detection-rules/wazuh-rules-manager";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getAiAvailability } from "@/lib/ai/service";
import { getPageAuthContext } from "@/lib/auth/session";
import { cn } from "@/lib/cn";
import { listDetectionRules } from "@/lib/detection-rules/service";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { getGithubRulesConfig } from "@/lib/github/contents";
import { listSiemRules } from "@/lib/siem-rules/service";
import { listWazuhRules } from "@/lib/wazuh-rules/service";

export const metadata: Metadata = { title: "Detection rules" };

const TABS = [
  { key: "wazuh", label: "Wazuh rules", href: "/detection-rules" },
  { key: "splunk", label: "Splunk rules", href: "/detection-rules?tab=splunk" },
  { key: "severity", label: "Severity rules", href: "/detection-rules?tab=severity" },
] as const;

export default async function DetectionRulesPage({ searchParams }: PageProps<"/detection-rules">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("rules:manage")) return <AccessDenied />;

  const { tab: rawTab } = await searchParams;
  const tab = rawTab === "severity" || rawTab === "splunk" ? rawTab : "wazuh";

  return (
    <>
      <PageHeader
        title="Detection rules"
        description={
          tab === "splunk"
            ? "Rules that run inside Splunk as saved searches. Fill in the fields (or have the AI draft them), read the savedsearches.conf stanza ArcRadar generates from them, then send it to GitHub, edit it or reject it. A script on the Splunk host pulls approved rules; ArcRadar never connects to Splunk, and nothing but the generated search can ever be in the file."
            : tab === "wazuh"
              ? "Rules that run inside Wazuh and decide whether an event becomes an alert. Write one by hand or have the AI draft it, read the XML, then send it to GitHub, edit it or reject it. The Manager pulls approved rules from the repository; ArcRadar never changes anything on the Wazuh host itself."
              : "Rules ArcRadar checks against every alert as it is created, whether it arrived from telemetry or was recorded by hand. A match can raise the alert's severity and is always traceable on the alert itself; nothing here changes what an alert already says beyond that."
        }
      />

      <nav aria-label="Rule type" className="mb-4 flex gap-1 border-b border-border">
        {TABS.map((item) => (
          <Link
            key={item.key}
            href={item.href}
            aria-current={item.key === tab ? "page" : undefined}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              item.key === tab
                ? "border-primary text-foreground"
                : "border-transparent text-muted hover:text-foreground",
            )}
          >
            {item.label}
          </Link>
        ))}
      </nav>

      {tab === "wazuh" ? (
        <WazuhTab auth={auth} />
      ) : tab === "splunk" ? (
        <SplunkTab auth={auth} />
      ) : (
        <SeverityTab auth={auth} />
      )}
    </>
  );
}

type Auth = NonNullable<Awaited<ReturnType<typeof getPageAuthContext>>>;

async function WazuhTab({ auth }: { auth: Auth }) {
  const config = getGithubRulesConfig(await getEffectiveEnv());
  const [rules, availability] = await Promise.all([
    listWazuhRules(auth.supabase),
    getAiAvailability(auth.supabase),
  ]);
  return (
    <WazuhRulesManager
      rules={rules}
      githubReady={config !== null}
      githubBlobBase={
        config ? `https://github.com/${config.owner}/${config.repo}/blob/${config.branch}` : null
      }
      aiReady={availability.ready && auth.permissions.has("ai:use")}
    />
  );
}

async function SplunkTab({ auth }: { auth: Auth }) {
  const config = getGithubRulesConfig(await getEffectiveEnv());
  const [rules, availability] = await Promise.all([
    listSiemRules(auth.supabase, "splunk"),
    getAiAvailability(auth.supabase),
  ]);
  return (
    <SiemRulesManager
      siem="splunk"
      rules={rules}
      githubReady={config !== null}
      githubBlobBase={
        config ? `https://github.com/${config.owner}/${config.repo}/blob/${config.branch}` : null
      }
      aiReady={availability.ready && auth.permissions.has("ai:use")}
    />
  );
}

async function SeverityTab({ auth }: { auth: Auth }) {
  const rules = await listDetectionRules(auth.supabase);
  return <DetectionRulesManager rules={rules} canManage={auth.permissions.has("rules:manage")} />;
}
