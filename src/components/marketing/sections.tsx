import { ArrowRight, ArrowUpRight, Ban, Check, Circle, CircleCheck, Minus } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { buttonClasses } from "@/components/ui/button";
import { Logo } from "@/components/ui/logo";
import { cn } from "@/lib/cn";
import { DOCS, GITHUB_URL, SETUP_GUIDE_URL } from "./links";
import { RuleFiles } from "./rule-files";

/** A section's title on the left and its opening paragraph on the right; stacked on small screens. */
function SectionHead({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <div className="grid gap-5 lg:grid-cols-12 lg:gap-10">
      <h2
        id={id}
        className="text-3xl leading-[1.1] font-semibold tracking-[-0.025em] text-balance sm:text-[2.5rem] lg:col-span-5"
      >
        {title}
      </h2>
      <p className="max-w-2xl text-lg/8 text-pretty text-muted lg:col-span-7 lg:pt-1.5">
        {children}
      </p>
    </div>
  );
}

function Section({
  id,
  labelledBy,
  className,
  children,
}: {
  id?: string;
  labelledBy: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      aria-labelledby={labelledBy}
      className={cn("scroll-mt-16 border-b border-border", className)}
    >
      <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:py-28">{children}</div>
    </section>
  );
}

/* ------------------------------------------------- who connects to whom */

type Party = { name: string; kind: "yours" | "arcradar" | "outside" };

const YOUR_SIEM: Party = { name: "Your SIEM", kind: "yours" };
const ARCRADAR: Party = { name: "ArcRadar", kind: "arcradar" };
const REPOSITORY: Party = { name: "Your rules repository", kind: "outside" };

const CONNECTIONS: { from: Party; to: Party; what: string }[] = [
  {
    from: YOUR_SIEM,
    to: ARCRADAR,
    what: "Each alert, over HTTPS, with an API key that can do one thing: send alerts. A Wazuh Manager uses an integration script, Splunk an alert action.",
  },
  {
    from: { name: "Your Splunk host", kind: "yours" },
    to: ARCRADAR,
    what: "The names of the fields it really has, and how a rule in test mode would have fired on the logs it already holds.",
  },
  {
    from: ARCRADAR,
    to: REPOSITORY,
    what: "Each rule you approve, as one commit and one file on GitHub. Withdrawing a rule deletes its file.",
  },
  {
    from: { name: "Your SIEM host", kind: "yours" },
    to: REPOSITORY,
    what: "A pull. A script on the host checks every file, tests it and only then loads it, and puts the old rules back if the SIEM refuses the new ones.",
  },
  {
    from: ARCRADAR,
    to: { name: "Intelligence sources", kind: "outside" },
    what: "Public addresses, domains and hashes to look up at VirusTotal, AbuseIPDB, AlienVault OTX and Shodan. Private and reserved values never leave.",
  },
];

const PARTY_STYLES: Record<Party["kind"], string> = {
  yours: "border-input-border bg-surface text-foreground",
  arcradar: "border-tone-brand-border bg-tone-brand-bg text-tone-brand-fg",
  outside: "border-border bg-surface-2 text-muted",
};

function PartyChip({ party }: { party: Party }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2.5 py-1 text-sm font-medium whitespace-nowrap",
        PARTY_STYLES[party.kind],
      )}
    >
      {party.name}
    </span>
  );
}

const FACTS = [
  {
    title: "Pushed, never polled",
    text: "The SIEM sends what it found. ArcRadar does not log in to it, so there is no SIEM password for ArcRadar to leak.",
  },
  {
    title: "A rule is a file you can read",
    text: "ArcRadar writes the Wazuh XML or the Splunk stanza itself from the fields you fill in, so a rule can hold a search and nothing else.",
  },
  {
    title: "About fifteen seconds",
    text: "The Splunk host keeps one request open to ArcRadar. Push a rule and it is installed and tested on real logs moments later.",
  },
];

export function Connections() {
  return (
    <Section id="how-it-works" labelledBy="how-title">
      <SectionHead id="how-title" title="Alerts come in. Rules go back out.">
        ArcRadar sits beside your SIEM, not inside it. Here is every connection it takes part in,
        and who starts each one. No row ends at your network.
      </SectionHead>

      <ul className="mt-14 border-t border-border">
        {CONNECTIONS.map((row) => (
          <li
            key={`${row.from.name}-${row.to.name}`}
            className="grid gap-3 border-b border-border py-5 lg:grid-cols-12 lg:items-center lg:gap-10"
          >
            <p className="flex flex-wrap items-center gap-x-2.5 gap-y-2 lg:col-span-5">
              <PartyChip party={row.from} />
              <ArrowRight aria-hidden className="size-4 shrink-0 text-primary" />
              <span className="sr-only">connects to</span>
              <PartyChip party={row.to} />
            </p>
            <p className="max-w-2xl text-pretty text-muted lg:col-span-7">{row.what}</p>
          </li>
        ))}
        <li className="grid gap-3 border-b border-border py-5 lg:grid-cols-12 lg:items-center lg:gap-10">
          <p className="flex flex-wrap items-center gap-x-2.5 gap-y-2 lg:col-span-5">
            <PartyChip party={{ name: "Anything", kind: "outside" }} />
            <Ban aria-hidden className="size-4 shrink-0 text-tone-red-fg" />
            <span className="sr-only">never connects to</span>
            <PartyChip party={YOUR_SIEM} />
          </p>
          <p className="max-w-2xl text-pretty lg:col-span-7">
            Nothing. There is no inbound firewall rule to write, and no port of your SIEM is opened
            to ArcRadar, to GitHub or to the internet.
          </p>
        </li>
      </ul>

      <dl className="mt-14 grid gap-x-10 gap-y-8 md:grid-cols-3">
        {FACTS.map((fact) => (
          <div key={fact.title}>
            <dt className="font-semibold">{fact.title}</dt>
            <dd className="mt-2 text-pretty text-muted">{fact.text}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

/* ------------------------------------------------- one alert, start to end */

function Chip({ tone, children }: { tone: string; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {children}
    </span>
  );
}

function Fragment({ children }: { children: ReactNode }) {
  return (
    <div
      aria-hidden
      className="rounded-lg border border-border bg-surface p-4 text-sm lg:col-span-5"
    >
      {children}
    </div>
  );
}

function VerdictBar({ name, value, width }: { name: string; value: string; width: string }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span>{name}</span>
        <span className="text-xs text-muted">{value}</span>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-2">
        <div className={cn("h-full rounded-full bg-tone-red-fg", width)} />
      </div>
    </div>
  );
}

/** A slice of the matrix: one technique lit, the rest quiet. */
const MATRIX_CELLS = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];

const TRACE: { title: string; text: string; fragment: ReactNode }[] = [
  {
    title: "It arrives",
    text: "The SIEM posts the alert. ArcRadar stores the event, opens an alert, records the machine it came from and pulls out the addresses, domains and hashes inside it.",
    fragment: (
      <>
        <div className="flex flex-wrap gap-1.5">
          <Chip tone="border-tone-orange-border bg-tone-orange-bg text-tone-orange-fg">High</Chip>
          <Chip tone="border-tone-blue-border bg-tone-blue-bg text-tone-blue-fg">New</Chip>
          <Chip tone="border-tone-violet-border bg-tone-violet-bg text-tone-violet-fg">
            External provider
          </Chip>
        </div>
        <p className="mt-3 font-medium">Five failed logons from one address</p>
        <p className="mt-1 text-xs text-muted">
          From Splunk, on <code>WIN10-LAB</code>, source address <code>185.220.101.4</code>
        </p>
      </>
    ),
  },
  {
    title: "Repeats fold into it",
    text: "The same alert again within the hour links to the first one instead of filling the queue. A severity rule you wrote can raise its severity. It can never lower it.",
    fragment: (
      <p className="flex items-center justify-between gap-3">
        <span>Duplicates linked to this alert</span>
        <span className="rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs">
          3
        </span>
      </p>
    ),
  },
  {
    title: "It is researched",
    text: "Seconds later the public indicators have been checked at VirusTotal, AbuseIPDB, AlienVault OTX and Shodan InternetDB, and the worst verdict is on the record. A verdict only ever moves up.",
    fragment: (
      <div className="space-y-3">
        <VerdictBar name="VirusTotal" value="11 of 91 engines" width="w-[12%]" />
        <VerdictBar name="AbuseIPDB" value="confidence 100 of 100" width="w-full" />
        <p className="text-xs text-muted">
          Verdict: <span className="font-medium text-tone-red-fg">Malicious</span>
        </p>
      </div>
    ),
  },
  {
    title: "It lands on the ATT&CK matrix",
    text: "The technique the rule named lights up, coloured by the worst alert behind it. The matrix shows what happened on your machines, not a catalogue of everything that could.",
    fragment: (
      <>
        <div className="grid grid-cols-7 gap-1">
          {MATRIX_CELLS.map((state, index) => (
            <span
              key={index}
              className={cn(
                "h-5 rounded-sm border",
                state === 1 && "border-tone-orange-border bg-tone-orange-bg",
                state === 2 && "border-tone-amber-border bg-tone-amber-bg",
                state === 0 && "border-border bg-surface-2",
              )}
            />
          ))}
        </div>
        <p className="mt-3 text-xs text-muted">
          <code className="text-foreground">T1110.001</code> Password Guessing, under Credential
          Access
        </p>
      </>
    ),
  },
  {
    title: "An analyst triages it",
    text: "SOC L1 acknowledges the alert, asks the AI for a summary or a false-positive score, then closes it, assigns it or hands it up. Every AI answer is checked against a schema, stored unchanged and labelled as AI.",
    fragment: (
      <>
        <p className="text-xs font-medium text-tone-violet-fg">AI-generated, analyst-assisted</p>
        <p className="mt-2 leading-relaxed">
          Repeated failed network logons against one account from a known Tor exit node fit password
          guessing. No successful logon followed.
        </p>
        <p className="mt-3 text-xs text-muted">Assigned to Leyla (SOC L1)</p>
      </>
    ),
  },
  {
    title: "It becomes a case",
    text: "SOC L2 opens an investigation with notes, evidence, a checklist and response actions that people tick off by hand, and writes the report when it closes. ArcRadar recommends and records. It never runs anything on a machine.",
    fragment: (
      <ul className="space-y-2">
        <li className="flex items-start gap-2.5 text-muted">
          <CircleCheck className="mt-0.5 size-4 shrink-0 text-tone-green-fg" />
          Block the source address at the perimeter
        </li>
        <li className="flex items-start gap-2.5 text-muted">
          <CircleCheck className="mt-0.5 size-4 shrink-0 text-tone-green-fg" />
          Confirm no successful logon followed the burst
        </li>
        <li className="flex items-start gap-2.5">
          <Circle className="mt-0.5 size-4 shrink-0 text-muted" />
          Review the lockout policy for the account
        </li>
      </ul>
    ),
  },
];

export function AlertTrace() {
  return (
    <Section labelledBy="trace-title" className="bg-surface/40">
      <SectionHead id="trace-title" title="One alert, from arrival to closed case">
        This is the path a burst of failed logons on a Windows machine takes through ArcRadar. The
        panels on the right are sketches of the real screens, with example values.
      </SectionHead>

      <ol className="mt-14 border-t border-border">
        {TRACE.map((step, index) => (
          <li
            key={step.title}
            className="grid gap-5 border-b border-border py-7 lg:grid-cols-12 lg:items-start lg:gap-10"
          >
            <div className="flex gap-5 lg:col-span-7">
              <span
                aria-hidden
                className="w-7 shrink-0 pt-0.5 font-mono text-sm text-primary tabular-nums"
              >
                {String(index + 1).padStart(2, "0")}
              </span>
              <div>
                <h3 className="text-lg font-semibold tracking-tight">{step.title}</h3>
                <p className="mt-2 max-w-xl text-pretty text-muted">{step.text}</p>
              </div>
            </div>
            <Fragment>{step.fragment}</Fragment>
          </li>
        ))}
      </ol>
    </Section>
  );
}

/* ------------------------------------------------- detection rules */

const RULE_LIFE = [
  {
    title: "Draft",
    text: "Fill in the form, or describe the rule in a sentence and let the AI fill it in. For Splunk the form offers the indexes, sourcetypes and fields your server really has.",
  },
  {
    title: "Push as test",
    text: "The rule is loaded but not scheduled and has no action. It cannot raise an alert.",
  },
  {
    title: "Read the result",
    text: "Splunk runs it over the last 24 hours and the last 7 days of real logs and reports how often it would have fired.",
  },
  {
    title: "Go live",
    text: "Now it is scheduled, and every hit is sent to ArcRadar as an alert with the rule's severity and ATT&CK technique.",
  },
  {
    title: "Withdraw",
    text: "Changed your mind? The file is deleted from the repository and the SIEM drops the rule on its next pull.",
  },
];

export function Rules() {
  return (
    <Section id="rules" labelledBy="rules-title">
      <SectionHead id="rules-title" title="Detection rules you can test before they fire">
        Write a rule for Wazuh or Splunk in ArcRadar, read the exact file it becomes, and send it to
        your Git repository. The SIEM picks it up from there. A rule nobody approved never leaves.
      </SectionHead>

      <div className="mt-14 grid gap-12 lg:grid-cols-12 lg:gap-10">
        <ol className="lg:col-span-5">
          {RULE_LIFE.map((step, index) => (
            <li key={step.title} className="relative flex gap-4 pb-7 last:pb-0">
              {index < RULE_LIFE.length - 1 && (
                <span
                  aria-hidden
                  className="absolute top-7 bottom-0 left-[0.6875rem] w-px bg-border"
                />
              )}
              <span
                aria-hidden
                className="relative mt-0.5 flex size-[1.4375rem] shrink-0 items-center justify-center rounded-full border border-tone-brand-border bg-tone-brand-bg font-mono text-[11px] text-tone-brand-fg"
              >
                {index + 1}
              </span>
              <div>
                <h3 className="font-semibold">{step.title}</h3>
                <p className="mt-1 text-pretty text-muted">{step.text}</p>
              </div>
            </li>
          ))}
        </ol>

        <div className="space-y-4 lg:col-span-7">
          <RuleFiles />
          <div aria-hidden className="rounded-xl border border-border bg-surface p-5 text-sm">
            <p className="font-medium">Test on real data</p>
            <p className="mt-2 text-muted">
              <span className="text-foreground">Last 24 hours:</span> would have fired 2 times, for
              example 203.0.113.55 ×12
            </p>
            <p className="mt-1 text-muted">
              <span className="text-foreground">Last 7 days:</span> would have fired 5 times
            </p>
          </div>
          <p className="text-sm text-pretty text-muted">
            Sketches with example values. Test mode and the test on real data are for Splunk rules;
            a Wazuh rule is checked by Wazuh itself before the Manager installs it.
          </p>
        </div>
      </div>
    </Section>
  );
}

/* ------------------------------------------------- roles */

const ROLE_COLUMNS = ["Viewer", "SOC L1", "SOC L2", "Admin"] as const;

/** One row per ability; a flag per role, in the order of ROLE_COLUMNS. */
const ABILITIES: { what: string; who: [boolean, boolean, boolean, boolean] }[] = [
  {
    what: "See alerts, cases, indicators, vulnerabilities and reports",
    who: [true, true, true, true],
  },
  { what: "Acknowledge, assign and close alerts", who: [false, true, true, true] },
  { what: "Ask the AI for an analysis", who: [false, true, true, true] },
  { what: "Open investigations, write indicators and reports", who: [false, false, true, true] },
  { what: "Run live lookups at intelligence sources", who: [false, false, true, true] },
  { what: "Write detection rules and send them to Git", who: [false, false, false, true] },
  {
    what: "Manage accounts, integrations and provider keys, read the audit log",
    who: [false, false, false, true],
  },
];

export function Roles() {
  return (
    <Section id="roles" labelledBy="roles-title" className="bg-surface/40">
      <SectionHead id="roles-title" title="Four roles, enforced by the database">
        A new account can do nothing until an administrator approves it and picks its role. The same
        rules are written as row-level security policies in Postgres, so they hold even where a
        screen forgets to check.
      </SectionHead>

      {/* relative: the screen-reader text in the cells is absolutely positioned and must scroll with the table. */}
      <div className="relative mt-14 overflow-x-auto">
        <table className="w-full min-w-[34rem] border-collapse text-left">
          <caption className="sr-only">What each role can do</caption>
          <thead>
            <tr className="border-b border-border">
              <th scope="col" className="py-3 pr-4 text-sm font-medium text-muted">
                What a person can do
              </th>
              {ROLE_COLUMNS.map((role) => (
                <th key={role} scope="col" className="w-24 px-2 py-3 text-center font-semibold">
                  {role}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ABILITIES.map((row) => (
              <tr key={row.what} className="border-b border-border">
                <th scope="row" className="py-3.5 pr-4 font-normal text-pretty">
                  {row.what}
                </th>
                {row.who.map((allowed, index) => (
                  <td key={ROLE_COLUMNS[index]} className="px-2 py-3.5 text-center">
                    {allowed ? (
                      <Check aria-hidden className="mx-auto size-[1.125rem] text-primary" />
                    ) : (
                      <Minus aria-hidden className="mx-auto size-4 text-input-border" />
                    )}
                    <span className="sr-only">{allowed ? "Yes" : "No"}</span>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

/* ------------------------------------------------- security and integrations */

const WORKS_WITH: { group: string; names: string }[] = [
  { group: "SIEMs", names: "Wazuh, Splunk Enterprise" },
  {
    group: "Threat intelligence",
    names:
      "VirusTotal, AbuseIPDB, AlienVault OTX, Shodan InternetDB, abuse.ch feeds, CISA KEV, NVD",
  },
  { group: "AI providers", names: "Groq, OpenAI, Anthropic, DeepSeek, or a local Ollama" },
  { group: "Rule delivery", names: "A GitHub repository you own" },
];

const SECURITY = [
  {
    title: "Authorization lives in the database",
    text: "Row-level security on every table. The checks in the app are the fast path; Postgres has the last word.",
  },
  {
    title: "An audit log nobody can edit",
    text: "Every write is recorded, and the table is append-only even for the service role.",
  },
  {
    title: "Keys are stored the way passwords are",
    text: "An API key is kept as a hash, has one scope and an expiry, and is checked again on every request. Provider keys you paste in the app are encrypted with AES-256-GCM before they are stored.",
  },
  {
    title: "No inline scripts or styles",
    text: "A nonce-based Content-Security-Policy on every response, HttpOnly and Secure session cookies, and HSTS.",
  },
  {
    title: "Rate limits that survive a restart",
    text: "One shared counter in Postgres covers sign-in, AI calls, alert creation and ingestion.",
  },
  {
    title: "Outbound calls on a short leash",
    text: "Fixed HTTPS addresses, no redirects, a deadline and a size cap. Nothing a person types ever becomes a host name.",
  },
];

export function Security() {
  return (
    <Section id="security" labelledBy="security-title">
      <SectionHead id="security-title" title="Built like the thing it protects">
        A security tool should meet the standard it asks of others. Each of these is a property of
        the code, with tests that fail if it stops being true.
      </SectionHead>

      <dl className="mt-14 grid gap-x-10 border-t border-border md:grid-cols-2">
        {SECURITY.map((item) => (
          <div key={item.title} className="border-b border-border py-6">
            <dt className="font-semibold">{item.title}</dt>
            <dd className="mt-2 max-w-xl text-pretty text-muted">{item.text}</dd>
          </div>
        ))}
      </dl>

      <h3 className="mt-16 text-xl font-semibold tracking-tight">What it connects to</h3>
      <p className="mt-2 max-w-2xl text-pretty text-muted">
        Every one of these is optional and can be switched off by an administrator. ArcRadar starts
        with none of them and still works.
      </p>
      <dl className="mt-6 border-t border-border">
        {WORKS_WITH.map((row) => (
          <div
            key={row.group}
            className="grid gap-1 border-b border-border py-4 sm:grid-cols-12 sm:gap-10"
          >
            <dt className="text-muted sm:col-span-3">{row.group}</dt>
            <dd className="sm:col-span-9">{row.names}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

/* ------------------------------------------------- set up */

const SETUP_STEPS = [
  {
    title: "Create a Supabase project",
    text: "Apply the schema with one command. Roles, policies and the audit log come with it.",
    href: DOCS.database,
    link: "Create the database",
  },
  {
    title: "Deploy to Vercel",
    text: "Press the deploy button and paste five settings. There is no server to keep running.",
    href: DOCS.deploy,
    link: "Deploy the app",
  },
  {
    title: "Add your team",
    text: "Make yourself the first administrator, then add accounts for your analysts with their roles.",
    href: DOCS.team,
    link: "First administrator",
  },
  {
    title: "Connect a SIEM",
    text: "Make an API key in ArcRadar and install the small script on your Wazuh Manager or Splunk server.",
    href: DOCS.splunk,
    link: "Splunk guide",
    secondHref: DOCS.wazuh,
    secondLink: "Wazuh guide",
  },
];

export function Setup() {
  return (
    <Section id="setup" labelledBy="setup-title" className="bg-surface/40">
      <SectionHead id="setup-title" title="Run your own copy">
        ArcRadar is open source and runs on the free plans of Vercel and Supabase. The whole setup
        is four steps, and each one is written down.
      </SectionHead>

      <ol className="mt-14 grid gap-x-10 gap-y-10 sm:grid-cols-2 lg:grid-cols-4">
        {SETUP_STEPS.map((step, index) => (
          <li key={step.title} className="border-t border-border pt-5">
            <span aria-hidden className="font-mono text-sm text-primary tabular-nums">
              {String(index + 1).padStart(2, "0")}
            </span>
            <h3 className="mt-2 font-semibold">{step.title}</h3>
            <p className="mt-2 text-pretty text-muted">{step.text}</p>
            <p className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-sm">
              <DocLink href={step.href}>{step.link}</DocLink>
              {step.secondHref && <DocLink href={step.secondHref}>{step.secondLink}</DocLink>}
            </p>
          </li>
        ))}
      </ol>

      <div className="mt-16 flex flex-col gap-3 sm:flex-row sm:items-center">
        <a
          href={SETUP_GUIDE_URL}
          target="_blank"
          rel="noreferrer"
          className={buttonClasses({ size: "lg" })}
        >
          Read the setup guide
          <ArrowUpRight aria-hidden className="size-4" />
        </a>
        <Link href="/login" className={buttonClasses({ variant: "secondary", size: "lg" })}>
          Sign in to this console
        </Link>
      </div>
    </Section>
  );
}

function DocLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 font-medium text-primary hover:underline"
    >
      {children}
      <ArrowUpRight aria-hidden className="size-3.5" />
    </a>
  );
}

/* ------------------------------------------------- footer */

export function LandingFooter() {
  return (
    <footer>
      <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 px-4 py-10 sm:px-6 md:flex-row md:items-center">
        <div className="space-y-2">
          <Logo />
          <p className="text-sm text-muted">
            A Holberton portfolio project by Agshin. Built with Next.js, Supabase and Vercel.
          </p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <Link href="/login" className="text-muted hover:text-foreground">
            Sign in
          </Link>
          <Link href="/signup" className="text-muted hover:text-foreground">
            Request access
          </Link>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-muted hover:text-foreground"
          >
            Source on GitHub
            <ArrowUpRight aria-hidden className="size-3.5" />
          </a>
        </nav>
      </div>
    </footer>
  );
}
