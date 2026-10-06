import { GitBranch, ShieldCheck, Users } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { LogoLink, RadarBackdrop } from "@/components/ui/logo";

const POINTS = [
  {
    icon: ShieldCheck,
    text: "Alerts from Wazuh and Splunk in one queue, researched and mapped to MITRE ATT&CK, each record showing where it came from.",
  },
  {
    icon: GitBranch,
    text: "Detection rules written here, tested on real logs and delivered to the SIEM through Git.",
  },
  {
    icon: Users,
    text: "Admin, SOC L2, SOC L1 and viewer roles. An administrator approves every account, and every change is in the audit trail.",
  },
];

/** Split layout for the signed-out pages: brand panel on large screens, form always. */
export default function AuthLayout({ children }: LayoutProps<"/">) {
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <aside className="relative hidden overflow-hidden border-r border-border bg-surface lg:flex lg:flex-col lg:justify-between lg:p-12">
        <RadarBackdrop className="absolute -right-24 -bottom-24 size-[36rem]" />
        <div className="relative">
          <LogoLink href="/" label="ArcRadar, back to the home page" />
        </div>
        <div className="relative max-w-md space-y-8">
          <div className="space-y-3">
            <p className="text-sm font-medium text-primary">Incident response beside your SIEM</p>
            <h2 className="text-4xl leading-tight font-semibold tracking-tight">
              Know what is on your radar.
            </h2>
          </div>
          <ul className="space-y-4">
            {POINTS.map(({ icon: Icon, text }) => (
              <li key={text} className="flex gap-3 text-sm text-muted">
                <Icon aria-hidden className="mt-0.5 size-4 shrink-0 text-primary" />
                {text}
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-muted">
          ArcRadar, incident response and case management
        </p>
      </aside>

      <main
        id="main"
        className="relative flex min-h-dvh flex-col items-center justify-center px-4 py-12 sm:px-8"
      >
        <div className="absolute top-3 right-3">
          <ThemeToggle />
        </div>
        <div className="w-full max-w-sm">
          <div className="mb-10 lg:hidden">
            <LogoLink href="/" label="ArcRadar, back to the home page" />
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
