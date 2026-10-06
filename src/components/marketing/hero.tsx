import Link from "next/link";
import { ThemeToggle } from "@/components/theme-toggle";
import { buttonClasses } from "@/components/ui/button";
import { LogoLink } from "@/components/ui/logo";
import { cn } from "@/lib/cn";
import { SETUP_GUIDE_URL } from "./links";

const NAV = [
  { href: "#how-it-works", label: "How it works" },
  { href: "#rules", label: "Detection rules" },
  { href: "#roles", label: "Roles" },
  { href: "#security", label: "Security" },
  { href: "#setup", label: "Set up" },
];

export function LandingHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <LogoLink href="/" label="ArcRadar home" />
        <nav aria-label="Sections" className="hidden items-center lg:flex">
          {NAV.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="rounded-lg px-3 py-2 text-sm text-muted transition-colors hover:text-foreground"
            >
              {item.label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-1.5">
          <ThemeToggle />
          {/*
           * A phone has room for one button, signing in; requesting access is in the hero. The
           * wrappers do the hiding: a `hidden` on the button itself loses to its own `inline-flex`.
           */}
          <span className="sm:hidden">
            <Link href="/login" className={buttonClasses({ size: "sm" })}>
              Sign in
            </Link>
          </span>
          <span className="hidden items-center gap-1.5 sm:flex">
            <Link href="/login" className={buttonClasses({ variant: "ghost", size: "sm" })}>
              Sign in
            </Link>
            <Link href="/signup" className={buttonClasses({ size: "sm" })}>
              Request access
            </Link>
          </span>
        </div>
      </div>
    </header>
  );
}

export function Hero() {
  return (
    <section className="relative isolate overflow-hidden border-b border-border">
      <div className="relative mx-auto grid max-w-6xl gap-14 px-4 pt-14 pb-16 sm:px-6 sm:pt-20 lg:grid-cols-12 lg:items-center lg:gap-10 lg:pt-24 lg:pb-24">
        <div className="lg:col-span-7">
          <h1 className="text-[2.6rem] leading-[1.03] font-semibold tracking-[-0.035em] sm:text-6xl lg:text-[4.1rem]">
            <span className="block text-balance">Your SIEM raises the alert.</span>
            <span className="block text-balance">ArcRadar works the case.</span>
          </h1>
          <p className="mt-6 max-w-xl text-lg/8 text-pretty text-muted">
            ArcRadar takes alerts from Wazuh and Splunk, looks up the addresses and hashes inside
            them, places them on the MITRE ATT&amp;CK matrix and gives your analysts a queue, a case
            file and an audit trail. Detection rules go back the other way, as reviewed files in
            Git.
          </p>
          <div className="mt-9 flex flex-col gap-3 sm:flex-row">
            <Link href="/login" className={buttonClasses({ size: "lg" })}>
              Sign in to the console
            </Link>
            <a
              href={SETUP_GUIDE_URL}
              target="_blank"
              rel="noreferrer"
              className={buttonClasses({ variant: "secondary", size: "lg" })}
            >
              Run your own copy
            </a>
          </div>
          <p className="mt-5 max-w-xl text-sm text-muted">
            No account yet?{" "}
            <Link href="/signup" className="font-medium text-primary hover:underline">
              Request access
            </Link>
            . An administrator approves every new account and chooses its role.
          </p>
        </div>

        <div className="lg:col-span-5">
          <Scope />
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ scope */

type Contact = {
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  source: string;
  technique: string;
  age: string;
  /** Text color for the severity; the dot is drawn in it. */
  tone: string;
  /** Where the contact sits on the scope: distance from the centre is its age. */
  position: string;
  /** Minus the time left until the beam reaches this bearing, so the dot lights as it passes. */
  phase: string;
  /** Which side of the dot its label sits on, so labels never run into each other or the rim. */
  label: "left" | "right";
};

/**
 * Four example alerts. Positions follow bearing and range on the scope (left = 50% + 50%·r·sin θ,
 * top = 50% − 50%·r·cos θ); the phase is θ/360 of the 10 s turn, minus 10 s.
 */
const CONTACTS: Contact[] = [
  {
    title: "Multiple Windows logon failures",
    severity: "Critical",
    source: "Wazuh",
    technique: "T1110",
    age: "2 min",
    tone: "text-tone-red-fg",
    position: "left-[55.2%] top-[42.6%]",
    phase: "[animation-delay:-9.03s]",
    label: "right",
  },
  {
    title: "Five failed logons from one address",
    severity: "High",
    source: "Splunk",
    technique: "T1110.001",
    age: "9 min",
    tone: "text-tone-orange-fg",
    position: "left-[30.7%] top-[44.8%]",
    phase: "[animation-delay:-2.08s]",
    label: "left",
  },
  {
    title: "Defender real-time protection turned off",
    severity: "Medium",
    source: "Wazuh",
    technique: "T1562.001",
    age: "41 min",
    tone: "text-tone-amber-fg",
    position: "left-[77.3%] top-[59.9%]",
    phase: "[animation-delay:-6.94s]",
    label: "left",
  },
  {
    title: "New service installed",
    severity: "Low",
    source: "Wazuh",
    technique: "T1543.003",
    age: "6 h",
    tone: "text-tone-blue-fg",
    position: "left-[25.3%] top-[85.2%]",
    phase: "[animation-delay:-4.03s]",
    label: "right",
  },
];

/** Range rings, innermost first: how long ago an alert arrived. */
const RINGS = [
  { label: "5 min", top: "top-[39%]" },
  { label: "30 min", top: "top-[26.5%]" },
  { label: "2 h", top: "top-[14%]" },
  { label: "24 h", top: "top-[2.5%]" },
];

/**
 * The alert queue drawn as a radar scope: the nearer the centre, the newer the alert, and the colour
 * is its severity. It is an illustration with example values, labelled as one, and the list under it
 * says the same thing in words for anyone who cannot see the picture.
 */
function Scope() {
  return (
    <figure className="relative mx-auto w-full max-w-md">
      <div aria-hidden className="scope-bezel mx-auto max-w-[23rem]">
        <div className="landing-rings" />
        <div className="scope">
          <div className="scope-sweep" />
          {RINGS.map((ring) => (
            <span
              key={ring.label}
              className={cn(
                "absolute right-1/2 mr-1.5 font-mono text-[10px] leading-none text-muted",
                ring.top,
              )}
            >
              {ring.label}
            </span>
          ))}
          {CONTACTS.map((contact) => (
            <span key={contact.title} className={cn("absolute", contact.position)}>
              <span
                className={cn(
                  "scope-contact absolute -top-[5px] -left-[5px] size-2.5 rounded-full bg-current",
                  contact.tone,
                  contact.phase,
                )}
              />
              <span
                className={cn(
                  "absolute -top-[7px] font-mono text-[11px] leading-none whitespace-nowrap text-foreground",
                  contact.label === "right" ? "left-3" : "right-3",
                )}
              >
                {contact.technique}
              </span>
            </span>
          ))}
        </div>
      </div>

      <ul className="mt-7 divide-y divide-border border-y border-border">
        {CONTACTS.map((contact) => (
          <li key={contact.title} className="flex items-center gap-3 py-2.5">
            <span
              aria-hidden
              className={cn("size-2 shrink-0 rounded-full bg-current", contact.tone)}
            />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium">{contact.title}</span>
              <span className="block text-xs text-muted">
                {contact.severity}, from {contact.source}
              </span>
            </span>
            <code className="hidden text-xs text-muted sm:block">{contact.technique}</code>
            <span className="w-14 shrink-0 text-right text-xs text-muted tabular-nums">
              {contact.age}
              <span className="sr-only"> ago</span>
            </span>
          </li>
        ))}
      </ul>
      <figcaption className="mt-3 text-xs text-muted">
        An illustration with example values, not live data. Each dot is an alert: the closer to the
        centre, the newer it is.
      </figcaption>
    </figure>
  );
}
