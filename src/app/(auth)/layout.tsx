import { Eye, ShieldCheck, Users } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Logo, RadarBackdrop } from "@/components/ui/logo";

const POINTS = [
  {
    icon: Eye,
    text: "Indicators, threat actors and vulnerabilities in one place, with every record showing where it came from.",
  },
  {
    icon: ShieldCheck,
    text: "Demo and local data are always labelled, and never presented as live intelligence.",
  },
  {
    icon: Users,
    text: "Role-based access for admins, analysts and viewers, with a full audit trail.",
  },
];

/** Split layout for the signed-out pages: brand panel on large screens, form always. */
export default function AuthLayout({ children }: LayoutProps<"/">) {
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <aside className="relative hidden overflow-hidden border-r border-border bg-surface lg:flex lg:flex-col lg:justify-between lg:p-12">
        <RadarBackdrop className="absolute -right-24 -bottom-24 size-[36rem]" />
        <Logo />
        <div className="relative max-w-md space-y-8">
          <div className="space-y-3">
            <p className="text-sm font-medium tracking-widest text-primary uppercase">
              Threat intelligence
            </p>
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
          ArcRadar · Cybersecurity intelligence platform
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
            <Logo />
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
