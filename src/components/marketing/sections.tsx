import {
  ArrowRight,
  ArrowUpRight,
  Bot,
  ClipboardCheck,
  Crosshair,
  Database,
  Eye,
  Fingerprint,
  GitBranch,
  Gauge,
  KeyRound,
  Layers,
  Lock,
  Monitor,
  ScrollText,
  Search,
  Server,
  ShieldCheck,
  Siren,
  Sparkles,
  Workflow,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { buttonClasses } from "@/components/ui/button";
import { Logo } from "@/components/ui/logo";
import { cn } from "@/lib/cn";
import { GITHUB_URL } from "./links";

function SectionHeading({
  id,
  eyebrow,
  title,
  children,
}: {
  id: string;
  eyebrow: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="text-xs font-semibold tracking-[0.2em] text-primary uppercase">{eyebrow}</p>
      <h2 id={id} className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
        {title}
      </h2>
      <p className="mt-4 text-pretty text-muted">{children}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ stats */

const STATS = [
  { value: "7", label: "AI analysis kinds, each schema-validated" },
  { value: "100%", label: "of tables behind row-level security" },
  { value: "0", label: "actions executed automatically" },
  { value: "1", label: "append-only audit trail for every write" },
];

export function StatsBand() {
  return (
    <section aria-label="At a glance" className="border-y border-border bg-surface">
      <dl className="mx-auto grid max-w-6xl grid-cols-2 gap-px bg-border lg:grid-cols-4">
        {STATS.map((stat) => (
          <div key={stat.label} className="bg-surface px-4 py-8 text-center sm:px-6">
            <dd className="text-4xl font-semibold tracking-tight text-primary">{stat.value}</dd>
            <dt className="mx-auto mt-2 max-w-[16rem] text-sm text-muted">{stat.label}</dt>
          </div>
        ))}
      </dl>
    </section>
  );
}

/* --------------------------------------------------------------- platform */

const TECHNIQUE_TONES = [
  "bg-surface-2",
  "bg-surface-2",
  "bg-tone-amber-bg border-tone-amber-border",
  "bg-surface-2",
  "bg-tone-red-bg border-tone-red-border",
  "bg-surface-2",
  "bg-tone-orange-bg border-tone-orange-border",
  "bg-surface-2",
  "bg-surface-2",
  "bg-tone-red-bg border-tone-red-border",
  "bg-surface-2",
  "bg-tone-amber-bg border-tone-amber-border",
  "bg-surface-2",
  "bg-surface-2",
  "bg-tone-orange-bg border-tone-orange-border",
  "bg-surface-2",
  "bg-surface-2",
  "bg-surface-2",
];

function MatrixPreview() {
  return (
    <div aria-hidden className="mt-6 grid grid-cols-6 gap-1.5">
      {TECHNIQUE_TONES.map((tone, index) => (
        <span key={index} className={cn("h-7 rounded-md border border-border", tone)} />
      ))}
    </div>
  );
}

function Card({
  icon: Icon,
  title,
  className,
  children,
}: {
  icon: LucideIcon;
  title: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <article
      className={cn(
        "group relative overflow-hidden rounded-2xl border border-border bg-surface p-6 transition-colors hover:border-tone-brand-border",
        className,
      )}
    >
      <span className="inline-flex size-10 items-center justify-center rounded-xl border border-tone-brand-border bg-tone-brand-bg text-tone-brand-fg">
        <Icon aria-hidden className="size-5" />
      </span>
      <h3 className="mt-5 text-lg font-semibold tracking-tight">{title}</h3>
      <div className="mt-2 text-sm leading-relaxed text-muted">{children}</div>
    </article>
  );
}

export function Platform() {
  return (
    <section id="platform" aria-labelledby="platform-title" className="scroll-mt-20 py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          id="platform-title"
          eyebrow="The platform"
          title="Everything an analyst does with an alert"
        >
          One workspace for the whole loop: see what happened, find out who it is, decide what it
          means and keep the record.
        </SectionHeading>

        <div className="mt-14 grid gap-4 md:grid-cols-2 lg:grid-cols-6">
          <Card icon={Siren} title="Alerts and case management" className="lg:col-span-3">
            Alerts follow a strict lifecycle. Repeats fold into the original instead of flooding the
            queue, and an investigation collects the alerts, indicators, notes and checklist for one
            incident, with its history written by the server.
          </Card>
          <Card
            icon={Crosshair}
            title="MITRE ATT&CK matrix from your alerts"
            className="lg:col-span-3"
          >
            Techniques your own machines actually triggered, colored by worst severity. Click a cell
            to open the alerts behind it.
            <MatrixPreview />
          </Card>
          <Card icon={Search} title="Research on arrival" className="lg:col-span-2">
            New indicators are checked at VirusTotal, AbuseIPDB, AlienVault OTX and Shodan
            InternetDB the moment they show up. Private and reserved values never leave the
            workspace.
          </Card>
          <Card icon={Bot} title="AI-assisted analysis" className="lg:col-span-2">
            Threat summary, ATT&amp;CK mapping, severity check, false-positive score, response
            actions, checklist and verdict. Groq, OpenAI, Anthropic, DeepSeek or a local Ollama.
          </Card>
          <Card icon={ClipboardCheck} title="Response actions, tracked" className="lg:col-span-2">
            Recommended steps become a checklist a person moves through by hand. ArcRadar recommends
            and records. It never runs anything.
          </Card>
          <Card icon={ScrollText} title="Reports" className="lg:col-span-2">
            Generated snapshots of what the caller could already read, kept as they were, ready to
            print.
          </Card>
          <Card icon={Layers} title="Provenance on every record" className="lg:col-span-2">
            Every record says whether it is demo, local or external, enforced by the database, so
            demo data can never pass as live intelligence.
          </Card>
          <Card icon={Gauge} title="A dashboard that tells the truth" className="lg:col-span-2">
            Headline counts are real, unfiltered totals. Charts are hand-drawn and use the same
            colors as the badges.
          </Card>
        </div>
      </div>
    </section>
  );
}

/* --------------------------------------------------------------- pipeline */

const PIPELINE: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Monitor, title: "Endpoint", text: "A Windows 10 machine runs the Wazuh Agent." },
  {
    icon: Server,
    title: "Wazuh Manager",
    text: "Rules fire; alerts above the threshold are pushed over HTTPS.",
  },
  {
    icon: KeyRound,
    title: "Ingest API",
    text: "Scoped API key, re-verified on every request, rate limited.",
  },
  {
    icon: Workflow,
    title: "Dedup and rules",
    text: "Repeats link to the first alert; severity rules may raise, never lower.",
  },
  {
    icon: Search,
    title: "Research",
    text: "Public indicators are checked at intelligence sources.",
  },
  {
    icon: Eye,
    title: "Investigate",
    text: "Triage with AI assistance, track response, write the report.",
  },
];

export function Pipeline() {
  return (
    <section
      id="pipeline"
      aria-labelledby="pipeline-title"
      className="scroll-mt-20 border-y border-border bg-surface py-24"
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          id="pipeline-title"
          eyebrow="How data flows"
          title="A real pipeline, end to end"
        >
          This is not a demo feed. An attack on a real Windows machine travels this path and lands
          in the console within seconds.
        </SectionHeading>

        <ol className="mt-16 grid gap-y-10 sm:grid-cols-2 lg:grid-cols-6 lg:gap-y-0">
          {PIPELINE.map((step, index) => (
            <li key={step.title} className="relative px-3 text-center">
              {index < PIPELINE.length - 1 && (
                <span
                  aria-hidden
                  className="landing-flow absolute top-6 left-[calc(50%+2rem)] hidden h-0.5 w-[calc(100%-4rem)] lg:block"
                />
              )}
              <span className="relative mx-auto flex size-12 items-center justify-center rounded-2xl border border-tone-brand-border bg-tone-brand-bg text-tone-brand-fg">
                <step.icon aria-hidden className="size-5" />
                <span className="absolute -top-2 -right-2 flex size-5 items-center justify-center rounded-full border border-border bg-background font-mono text-[10px] text-muted">
                  {index + 1}
                </span>
              </span>
              <h3 className="mt-4 text-sm font-semibold">{step.title}</h3>
              <p className="mx-auto mt-1.5 max-w-[14rem] text-xs leading-relaxed text-muted">
                {step.text}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

/* ---------------------------------------------------------- rules as code */

const RULE_LINES = [
  '<group name="arcradar,">',
  '  <rule id="100241" level="10" frequency="5" timeframe="300">',
  "    <if_matched_sid>60122</if_matched_sid>",
  "    <same_field>win.eventdata.ipAddress</same_field>",
  "    <description>5 failed logons from one IP in 5 min</description>",
  "    <mitre><id>T1110</id></mitre>",
  "  </rule>",
  "</group>",
];

/** Tiny highlighter for the sample: tags, attribute names, quoted values. Tokens only. */
function RuleLine({ line }: { line: string }) {
  const parts = line.split(/(<\/?[\w-]+|[\w-]+(?==")|"[^"]*"|\/?>)/g).filter(Boolean);
  return (
    <>
      {parts.map((part, index) => {
        let tone = "text-foreground";
        if (/^<\/?[\w-]+$/.test(part) || part === ">" || part === "/>") tone = "text-tone-blue-fg";
        else if (/^[\w-]+$/.test(part) && line.includes(`${part}="`)) tone = "text-tone-amber-fg";
        else if (part.startsWith('"')) tone = "text-tone-green-fg";
        return (
          <span key={index} className={tone}>
            {part}
          </span>
        );
      })}
    </>
  );
}

const RULE_STEPS = [
  { title: "Draft", text: "Written by hand or drafted by AI from a sentence." },
  { title: "Review", text: "Checked against a strict schema and a regex guard." },
  { title: "GitHub", text: "Committed to a repository as arcradar_<id>.xml." },
  { title: "Manager pulls", text: "A script on the Manager tests and installs it." },
];

export function RulesAsCode() {
  return (
    <section id="rules-as-code" aria-labelledby="rules-title" className="scroll-mt-20 py-24">
      <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 sm:px-6 lg:grid-cols-2">
        <div>
          <p className="text-xs font-semibold tracking-[0.2em] text-primary uppercase">
            Detection as code
          </p>
          <h2
            id="rules-title"
            className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl"
          >
            Write a sentence. Get a Wazuh rule.
          </h2>
          <p className="mt-4 text-pretty text-muted">
            Describe what you want to catch and ArcRadar drafts the rule, checks it, and after your
            review commits it to Git. The Manager pulls it on its own schedule. ArcRadar never
            reaches into the Manager, and it renders the XML itself, so an active response can never
            be hiding in a rule.
          </p>

          <ol className="mt-8 grid gap-3 sm:grid-cols-2">
            {RULE_STEPS.map((step, index) => (
              <li key={step.title} className="rounded-xl border border-border bg-surface p-4">
                <p className="flex items-center gap-2 text-sm font-semibold">
                  <span className="flex size-5 items-center justify-center rounded-full bg-tone-brand-bg font-mono text-[11px] text-tone-brand-fg">
                    {index + 1}
                  </span>
                  {step.title}
                </p>
                <p className="mt-1.5 text-xs leading-relaxed text-muted">{step.text}</p>
              </li>
            ))}
          </ol>
        </div>

        <figure className="overflow-hidden rounded-2xl border border-border bg-surface shadow-xl shadow-black/20">
          <figcaption className="flex items-center justify-between gap-3 border-b border-border bg-surface-2 px-4 py-2.5">
            <span className="flex items-center gap-2 font-mono text-xs text-muted">
              <GitBranch aria-hidden className="size-3.5" />
              rules/arcradar_100241.xml
            </span>
            <span className="rounded-full border border-tone-green-border bg-tone-green-bg px-2 py-0.5 text-[11px] font-medium text-tone-green-fg">
              installed
            </span>
          </figcaption>
          <pre className="overflow-x-auto p-5 text-[13px] leading-7">
            <code className="block">
              {RULE_LINES.map((line, index) => (
                <span key={index} className="block whitespace-pre">
                  <RuleLine line={line} />
                </span>
              ))}
            </code>
          </pre>
        </figure>
      </div>
    </section>
  );
}

/* --------------------------------------------------------------- security */

const SECURITY: { icon: LucideIcon; title: string; text: string }[] = [
  {
    icon: Database,
    title: "Authorization lives in the database",
    text: "Row-level security on every table. The app's guards are a fast check; the database is the authority.",
  },
  {
    icon: Lock,
    title: "Nonce-based CSP",
    text: "No unsafe-inline anywhere. HttpOnly, Secure session cookies and HSTS in production.",
  },
  {
    icon: Gauge,
    title: "Shared rate limiting",
    text: "A Postgres-backed counter covers sign-in, AI endpoints, alert creation and ingestion.",
  },
  {
    icon: Fingerprint,
    title: "Append-only audit log",
    text: "Every authorized write is recorded, and even the service role cannot rewrite history.",
  },
  {
    icon: KeyRound,
    title: "Hashed, scoped API keys",
    text: "Only a hash is stored. Keys carry one scope, expire, and are re-verified on every request.",
  },
  {
    icon: ShieldCheck,
    title: "Reviewed outbound calls",
    text: "Fixed HTTPS bases, no redirects, deadlines and size caps. User input never becomes a host.",
  },
];

export function Security() {
  return (
    <section
      id="security"
      aria-labelledby="security-title"
      className="scroll-mt-20 border-y border-border bg-surface py-24"
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading
          id="security-title"
          eyebrow="Engineering"
          title="Built like the thing it protects"
        >
          A security tool should hold itself to the standard it asks of others. These are properties
          of the code, each covered by tests.
        </SectionHeading>

        <ul className="mt-14 grid gap-x-8 gap-y-10 sm:grid-cols-2 lg:grid-cols-3">
          {SECURITY.map((item) => (
            <li key={item.title} className="flex gap-4">
              <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background text-primary">
                <item.icon aria-hidden className="size-[1.1rem]" />
              </span>
              <div>
                <h3 className="text-sm font-semibold">{item.title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{item.text}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------ honest data */

export function HonestByDesign() {
  return (
    <section aria-labelledby="honest-title" className="py-24">
      <div className="mx-auto max-w-4xl px-4 text-center sm:px-6">
        <p className="text-xs font-semibold tracking-[0.2em] text-primary uppercase">
          Honest by design
        </p>
        <h2
          id="honest-title"
          className="mt-3 text-3xl font-semibold tracking-tight text-balance sm:text-4xl"
        >
          You always know where a record came from
        </h2>
        <p className="mx-auto mt-4 max-w-2xl text-pretty text-muted">
          Three labels, enforced by the database. Clients can only create local records, and demo
          data is never shown as intelligence.
        </p>

        <ul className="mt-10 grid gap-4 text-left sm:grid-cols-3">
          <li className="rounded-2xl border border-border bg-surface p-5">
            <span className="rounded-full border border-tone-violet-border bg-tone-violet-bg px-2.5 py-0.5 text-xs font-medium text-tone-violet-fg">
              External
            </span>
            <p className="mt-3 text-sm text-muted">
              Arrived from a sensor, a public feed or a live lookup. Written only by the server.
            </p>
          </li>
          <li className="rounded-2xl border border-border bg-surface p-5">
            <span className="rounded-full border border-tone-blue-border bg-tone-blue-bg px-2.5 py-0.5 text-xs font-medium text-tone-blue-fg">
              Local
            </span>
            <p className="mt-3 text-sm text-muted">Typed in by a person on this workspace.</p>
          </li>
          <li className="rounded-2xl border border-border bg-surface p-5">
            <span className="rounded-full border border-tone-amber-border bg-tone-amber-bg px-2.5 py-0.5 text-xs font-medium text-tone-amber-fg">
              Demo
            </span>
            <p className="mt-3 text-sm text-muted">
              Fictional sample data, always labelled as such.
            </p>
          </li>
        </ul>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------ CTA + footer */

export function FinalCta() {
  return (
    <section
      aria-labelledby="cta-title"
      className="relative overflow-hidden border-t border-border bg-surface"
    >
      <div aria-hidden className="landing-glow absolute inset-0 opacity-70" />
      <div className="relative mx-auto max-w-3xl px-4 py-24 text-center sm:px-6">
        <Sparkles aria-hidden className="mx-auto size-7 text-primary" />
        <h2
          id="cta-title"
          className="mt-5 text-3xl font-semibold tracking-tight text-balance sm:text-4xl"
        >
          See what is on your radar
        </h2>
        <p className="mx-auto mt-4 max-w-xl text-pretty text-muted">
          New accounts start as read-only viewers, so it is safe to look around.
        </p>
        <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
          <Link
            href="/signup"
            className={buttonClasses({ size: "lg", className: "w-full sm:w-auto" })}
          >
            Create an account
            <ArrowRight aria-hidden className="size-4" />
          </Link>
          <Link
            href="/login"
            className={buttonClasses({
              variant: "secondary",
              size: "lg",
              className: "w-full sm:w-auto",
            })}
          >
            Sign in
          </Link>
        </div>
      </div>
    </section>
  );
}

export function LandingFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 px-4 py-10 sm:px-6 md:flex-row md:items-center">
        <div className="space-y-2">
          <Logo />
          <p className="text-xs text-muted">
            A Holberton portfolio project by Agshin. Built with Next.js, Supabase and Vercel.
          </p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <Link href="/login" className="text-muted hover:text-foreground">
            Sign in
          </Link>
          <Link href="/signup" className="text-muted hover:text-foreground">
            Sign up
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
