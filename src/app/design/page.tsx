import { Bug, Radar } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import type { ReactNode } from "react";
import { PasswordRules } from "@/components/ui/password-field";
import { ThemeToggle } from "@/components/theme-toggle";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertStatusBadge,
  InvestigationStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { TextField } from "@/components/ui/input";
import { PasswordField } from "@/components/ui/password-field";
import { Logo } from "@/components/ui/logo";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { AccessDenied, EmptyState, ErrorState } from "@/components/ui/states";
import { Spinner } from "@/components/ui/spinner";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";

export const metadata: Metadata = { title: "Design system", robots: { index: false } };

const SURFACES = [
  ["background", "bg-background"],
  ["surface", "bg-surface"],
  ["surface-2", "bg-surface-2"],
  ["border", "bg-border"],
  ["input-border", "bg-input-border"],
  ["muted", "bg-muted"],
  ["foreground", "bg-foreground"],
  ["primary", "bg-primary"],
] as const;

const TONES: Tone[] = ["slate", "brand", "blue", "green", "amber", "orange", "red", "violet"];

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={`sec-${title}`} className="space-y-4">
      <h2 id={`sec-${title}`} className="border-b border-border pb-2 text-lg font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

/**
 * Living reference for the design system: every primitive and state in one page, for checking both
 * themes by eye. Development only; it is a 404 in production builds.
 */
export default function DesignPage() {
  if (process.env.NODE_ENV === "production") notFound();

  return (
    <main id="main" className="mx-auto max-w-5xl space-y-12 px-4 py-8 sm:px-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <Logo />
        <ThemeToggle />
      </header>
      <PageHeader
        title="Design system"
        description="Tokens, primitives and states. Toggle the theme to check both; run npm run check:contrast after changing any color."
      />

      <Section title="Color tokens">
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {SURFACES.map(([name, swatch]) => (
            <li key={name} className="space-y-1.5">
              <div className={`h-12 rounded-lg border border-border ${swatch}`} />
              <p className="font-mono text-xs text-muted">{name}</p>
            </li>
          ))}
        </ul>
        <div className="flex flex-wrap gap-2">
          {TONES.map((tone) => (
            <Badge key={tone} tone={tone} dot>
              {tone}
            </Badge>
          ))}
        </div>
      </Section>

      <Section title="Typography">
        <div className="space-y-2">
          <p className="text-3xl font-semibold tracking-tight">Heading 1 — 30px semibold</p>
          <p className="text-xl font-semibold">Heading 2 — 20px semibold</p>
          <p className="text-base">
            Body — Geist Sans 16px. Investigate the indicator, then decide.
          </p>
          <p className="text-sm text-muted">
            Secondary — 14px muted, used for descriptions and hints.
          </p>
          <p>
            Monospace for identifiers: <code>185.199.108.153</code> · <code>evil.example</code> ·{" "}
            <code className="break-all">
              44d88612fea8a8f36de82e1278abb02f0f2e2a1b0f7cbb5d4c8e6a0a9c1a4b7e
            </code>
          </p>
        </div>
      </Section>

      <Section title="Buttons">
        <div className="flex flex-wrap items-center gap-3">
          <Button>Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button loading>Loading</Button>
          <Button disabled>Disabled</Button>
          <Button size="sm">Small</Button>
          <Button size="lg">Large</Button>
        </div>
      </Section>

      <Section title="Form fields">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            id="d-email"
            label="Email"
            placeholder="you@example.com"
            hint="We never share it."
          />
          <TextField
            id="d-error"
            label="With an error"
            defaultValue="not-an-email"
            error="Enter a valid email address."
          />
          <PasswordField id="d-password" label="Password" defaultValue="Correct-Horse-1" />
          <div className="space-y-2">
            <p className="text-sm font-medium">Password rules</p>
            <PasswordRules value="Sh0rt" />
          </div>
        </div>
      </Section>

      <Section title="Badges: severity, verdict, provenance, status">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {(["info", "low", "medium", "high", "critical"] as const).map((severity) => (
              <SeverityBadge key={severity} severity={severity} />
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {(["unknown", "benign", "suspicious", "malicious"] as const).map((verdict) => (
              <VerdictBadge key={verdict} verdict={verdict} />
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {(["demo", "local", "external"] as const).map((origin) => (
              <OriginBadge key={origin} origin={origin} />
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {(["new", "acknowledged", "investigating", "resolved", "false_positive"] as const).map(
              (status) => (
                <AlertStatusBadge key={status} status={status} />
              ),
            )}
            {(["open", "contained", "closed"] as const).map((status) => (
              <InvestigationStatusBadge key={status} status={status} />
            ))}
          </div>
        </div>
      </Section>

      <Section title="Alerts">
        <div className="grid gap-3 sm:grid-cols-2">
          <Alert tone="info" title="Heads up">
            Informational message.
          </Alert>
          <Alert tone="success" title="Saved">
            The indicator was added.
          </Alert>
          <Alert tone="warning" title="Demo data">
            These records are samples.
          </Alert>
          <Alert tone="error" title="Could not sign in">
            Invalid email or password.
          </Alert>
        </div>
      </Section>

      <Section title="Table">
        <Table caption="Sample indicators (demo data)">
          <THead>
            <tr>
              <Th>Indicator</Th>
              <Th>Verdict</Th>
              <Th>Severity</Th>
              <Th>Source</Th>
            </tr>
          </THead>
          <TBody>
            <Tr>
              <Td>
                <code>203.0.113.42</code>
              </Td>
              <Td>
                <VerdictBadge verdict="malicious" />
              </Td>
              <Td>
                <SeverityBadge severity="critical" />
              </Td>
              <Td>
                <OriginBadge origin="demo" />
              </Td>
            </Tr>
            <Tr>
              <Td>
                <code>updates.example.test</code>
              </Td>
              <Td>
                <VerdictBadge verdict="suspicious" />
              </Td>
              <Td>
                <SeverityBadge severity="medium" />
              </Td>
              <Td>
                <OriginBadge origin="local" />
              </Td>
            </Tr>
            <Tr>
              <Td>
                <code>198.51.100.7</code>
              </Td>
              <Td>
                <VerdictBadge verdict="benign" />
              </Td>
              <Td>
                <SeverityBadge severity="info" />
              </Td>
              <Td>
                <OriginBadge origin="external" />
              </Td>
            </Tr>
          </TBody>
        </Table>
      </Section>

      <Section title="Cards and states">
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Card title</CardTitle>
              <CardDescription>Supporting description.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm">Cards group related content on the surface color.</p>
              <div className="flex items-center gap-2 text-sm text-muted">
                <Spinner /> Loading state
              </div>
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-1/2" />
            </CardContent>
          </Card>
          <Card>
            <EmptyState
              icon={Radar}
              title="No indicators yet"
              description="Add an indicator to start tracking it."
              action={<Button size="sm">Add indicator</Button>}
            />
          </Card>
          <Card>
            <ErrorState
              title="Could not load alerts"
              description="The request failed. Try again."
              detail="Reference: 1234567890"
              action={<Button size="sm">Try again</Button>}
            />
          </Card>
          <Card>
            <AccessDenied icon={Bug} />
          </Card>
        </div>
      </Section>
    </main>
  );
}
