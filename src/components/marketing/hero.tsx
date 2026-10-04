import {
  ArrowRight,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  Circle,
  Radar,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { buttonClasses } from "@/components/ui/button";
import { Logo } from "@/components/ui/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { GITHUB_URL } from "./links";

const NAV = [
  { href: "#platform", label: "Platform" },
  { href: "#pipeline", label: "Pipeline" },
  { href: "#rules-as-code", label: "Rules as code" },
  { href: "#security", label: "Security" },
];

export function LandingHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <Link href="/" aria-label="ArcRadar home">
          <Logo />
        </Link>
        <nav aria-label="Sections" className="hidden items-center gap-1 md:flex">
          {NAV.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3 py-2 text-sm text-muted transition-colors hover:bg-surface-2 hover:text-foreground"
            >
              {item.label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-1.5">
          <ThemeToggle />
          <Link
            href="/login"
            className={buttonClasses({
              variant: "ghost",
              size: "sm",
              className: "hidden sm:inline-flex",
            })}
          >
            Sign in
          </Link>
          <Link href="/signup" className={buttonClasses({ size: "sm" })}>
            Get started
          </Link>
        </div>
      </div>
    </header>
  );
}

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div aria-hidden className="landing-glow absolute inset-0" />
      <div aria-hidden className="landing-grid absolute inset-0" />

      <div className="relative mx-auto max-w-6xl px-4 pt-16 pb-10 text-center sm:px-6 sm:pt-24">
        <p
          className="landing-rise mx-auto inline-flex items-center gap-2 rounded-full border border-tone-brand-border bg-tone-brand-bg px-3.5 py-1.5 text-xs font-medium tracking-wide text-tone-brand-fg"
          style={{ animationDelay: "0ms" }}
        >
          <span className="landing-pulse-dot size-1.5 rounded-full bg-primary" />
          Incident response · Case management
          <span className="hidden sm:inline"> · Wazuh-native</span>
        </p>

        <h1
          className="landing-rise mx-auto mt-7 max-w-4xl text-4xl leading-[1.05] font-semibold tracking-tight text-balance sm:text-6xl lg:text-7xl"
          style={{ animationDelay: "80ms" }}
        >
          From raw alerts to{" "}
          <span className="bg-gradient-to-r from-primary to-tone-blue-fg bg-clip-text text-transparent">
            resolved incidents
          </span>
          .
        </h1>

        <p
          className="landing-rise mx-auto mt-6 max-w-2xl text-base text-pretty text-muted sm:text-lg"
          style={{ animationDelay: "160ms" }}
        >
          ArcRadar sits beside your SIEM. Telemetry from real endpoints lands here, gets researched
          at threat-intelligence sources, mapped to MITRE ATT&amp;CK, triaged with AI assistance and
          tracked to closure. Everything is role-gated and audited, and nothing runs on its own.
        </p>

        <div
          className="landing-rise mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row"
          style={{ animationDelay: "240ms" }}
        >
          <Link
            href="/login"
            className={buttonClasses({ size: "lg", className: "w-full sm:w-auto" })}
          >
            Sign in to the console
            <ArrowRight aria-hidden className="size-4" />
          </Link>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className={buttonClasses({
              variant: "secondary",
              size: "lg",
              className: "w-full sm:w-auto",
            })}
          >
            View source
            <ArrowUpRight aria-hidden className="size-4" />
          </a>
        </div>

        <ul
          className="landing-rise mt-10 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-muted"
          style={{ animationDelay: "320ms" }}
          aria-label="Built with"
        >
          {[
            "Wazuh",
            "MITRE ATT&CK",
            "VirusTotal",
            "AbuseIPDB",
            "AlienVault OTX",
            "abuse.ch",
            "CISA KEV",
          ].map((name) => (
            <li key={name} className="font-mono tracking-wide">
              {name}
            </li>
          ))}
        </ul>
      </div>

      <div
        className="landing-rise relative mx-auto max-w-5xl px-4 pb-20 sm:px-6"
        style={{ animationDelay: "420ms" }}
      >
        <ProductPreview />
      </div>
    </section>
  );
}

/**
 * A hand-built, illustrative picture of an alert page. It is not a screenshot and shows no real
 * data; it is labelled as illustrative so it can never be mistaken for live intelligence.
 */
function ProductPreview() {
  return (
    <figure className="relative">
      <div
        aria-hidden
        className="absolute -inset-x-6 -inset-y-4 -z-10 rounded-[2rem] bg-primary/10 blur-3xl"
      />
      <div className="overflow-hidden rounded-2xl border border-border bg-surface text-left shadow-2xl shadow-black/30">
        <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-4 py-2.5">
          <span className="size-2.5 rounded-full bg-tone-red-fg/70" />
          <span className="size-2.5 rounded-full bg-tone-amber-fg/70" />
          <span className="size-2.5 rounded-full bg-tone-green-fg/70" />
          <span className="ml-3 truncate rounded-md bg-background px-3 py-1 font-mono text-xs text-muted">
            arcradar.vercel.app/alerts/…
          </span>
        </div>

        <div className="grid gap-px bg-border lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <div className="space-y-5 bg-surface p-5 sm:p-6">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-tone-red-border bg-tone-red-bg px-2.5 py-0.5 text-xs font-semibold text-tone-red-fg">
                <ShieldAlert aria-hidden className="size-3.5" />
                Critical
              </span>
              <span className="rounded-full border border-tone-blue-border bg-tone-blue-bg px-2.5 py-0.5 text-xs font-medium text-tone-blue-fg">
                Investigating
              </span>
              <span className="rounded-full border border-tone-violet-border bg-tone-violet-bg px-2.5 py-0.5 text-xs font-medium text-tone-violet-fg">
                External · Wazuh
              </span>
            </div>

            <div>
              <h2 className="text-lg font-semibold tracking-tight sm:text-xl">
                Multiple Windows logon failures
              </h2>
              <p className="mt-1 text-sm text-muted">
                Asset <code>WIN10-LAB</code> · rule <code>60204</code> · 5 events in 4 minutes
              </p>
            </div>

            <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
              <PreviewFact label="Technique">
                <span className="rounded-md border border-tone-brand-border bg-tone-brand-bg px-1.5 py-0.5 font-mono text-xs text-tone-brand-fg">
                  T1110
                </span>{" "}
                Brute Force
              </PreviewFact>
              <PreviewFact label="Source address">
                <code>185.220.101.4</code>
              </PreviewFact>
              <PreviewFact label="Researched">
                <span className="text-tone-red-fg">Malicious</span> · 11/91
              </PreviewFact>
            </dl>

            <div className="rounded-xl border border-border bg-background p-4">
              <p className="flex items-center gap-2 text-xs font-medium tracking-wide text-muted uppercase">
                <Radar aria-hidden className="size-3.5 text-primary" />
                Threat intelligence
              </p>
              <ul className="mt-3 space-y-2.5 text-sm">
                <VerdictRow name="VirusTotal" value="11 / 91 engines" width="w-[12%]" />
                <VerdictRow name="AbuseIPDB" value="confidence 100 / 100" width="w-full" />
                <VerdictRow name="AlienVault OTX" value="3 pulses" width="w-1/4" />
              </ul>
            </div>
          </div>

          <div className="space-y-4 bg-surface p-5 sm:p-6">
            <div className="rounded-xl border border-tone-violet-border bg-tone-violet-bg/60 p-4">
              <p className="flex items-center gap-2 text-xs font-semibold tracking-wide text-tone-violet-fg uppercase">
                <Bot aria-hidden className="size-4" />
                AI-generated · analyst-assisted
              </p>
              <p className="mt-2.5 text-sm leading-relaxed text-foreground/90">
                Repeated failed network logons from a known Tor exit node against a single account
                fit password guessing. No successful logon followed. Severity looks appropriate.
              </p>
            </div>

            <div>
              <p className="text-xs font-medium tracking-wide text-muted uppercase">
                Response actions · tracked by hand
              </p>
              <ul className="mt-3 space-y-2 text-sm">
                <ActionRow done>Block the source address at the perimeter</ActionRow>
                <ActionRow done>Confirm no successful logon after the burst</ActionRow>
                <ActionRow>Review lockout policy for the account</ActionRow>
              </ul>
            </div>
          </div>
        </div>
      </div>
      <figcaption className="mt-4 text-center text-xs text-muted">
        Illustrative interface. Values are examples, not live data.
      </figcaption>
    </figure>
  );
}

function PreviewFact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-1 font-medium">{children}</dd>
    </div>
  );
}

function VerdictRow({ name, value, width }: { name: string; value: string; width: string }) {
  return (
    <li>
      <div className="flex items-center justify-between gap-3">
        <span>{name}</span>
        <span className="text-xs text-muted">{value}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-2">
        <div className={`h-full rounded-full bg-tone-red-fg ${width}`} />
      </div>
    </li>
  );
}

function ActionRow({ done, children }: { done?: boolean; children: React.ReactNode }) {
  const Icon = done ? CheckCircle2 : Circle;
  return (
    <li className="flex items-start gap-2.5">
      <Icon
        aria-hidden
        className={
          done ? "mt-0.5 size-4 shrink-0 text-tone-green-fg" : "mt-0.5 size-4 shrink-0 text-muted"
        }
      />
      <span className={done ? "text-muted line-through decoration-border" : ""}>{children}</span>
    </li>
  );
}
