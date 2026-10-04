import { Lightbulb } from "lucide-react";
import { headers } from "next/headers";
import Link from "next/link";
import { notFound } from "next/navigation";
import { IntelResult } from "@/components/intel/intel-result";
import { LookupForm } from "@/components/intel/lookup-form";
import { Alert } from "@/components/ui/alert";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { INTEL_DESCRIPTIONS, INTEL_KIND_LABELS, intelHref } from "@/lib/intel/constants";
import { DEMO_EXAMPLES } from "@/lib/intel/providers/demo-data";
import { intelKindSchema, lookupIntel } from "@/lib/intel/service";
import { parseTarget } from "@/lib/intel/target";
import { firstValues } from "@/lib/validation/query";

export default async function IntelligencePage({
  params,
  searchParams,
}: PageProps<"/intelligence/[kind]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("indicators:read")) return <AccessDenied />;

  const parsedKind = intelKindSchema.safeParse((await params).kind);
  if (!parsedKind.success) notFound();
  const kind = parsedKind.data;

  const input = (firstValues(await searchParams).q ?? "").trim();
  const parsed = input ? parseTarget(kind, input) : null;
  const result =
    parsed?.ok === true
      ? await lookupIntel(auth, parsed.target, { headers: await headers() })
      : null;

  return (
    <>
      <title>{`${INTEL_KIND_LABELS[kind]} · ArcRadar`}</title>
      <PageHeader title={INTEL_KIND_LABELS[kind]} description={INTEL_DESCRIPTIONS[kind]} />

      <div className="space-y-6">
        <LookupForm kind={kind} initialValue={input} />

        {parsed && !parsed.ok && (
          <Alert tone="error" title="That value can't be looked up here">
            {parsed.error}
            {parsed.suggestion && (
              <>
                {" "}
                <Link
                  href={intelHref(parsed.suggestion.kind, parsed.suggestion.value)}
                  prefetch={false}
                  className="font-medium underline"
                >
                  Open {INTEL_KIND_LABELS[parsed.suggestion.kind]} for it
                </Link>
                .
              </>
            )}
          </Alert>
        )}

        {result && (
          <IntelResult result={result} canAdd={auth.permissions.has("indicators:write")} />
        )}

        {!input && (
          <div className="rounded-xl border border-dashed border-border p-5">
            <p className="mb-3 flex items-center gap-2 text-sm font-medium">
              <Lightbulb aria-hidden className="size-4 text-muted" />
              Try a sample from the demo dataset
            </p>
            <ul className="space-y-1.5">
              {DEMO_EXAMPLES[kind].map((example) => (
                <li key={example}>
                  <Link
                    href={intelHref(kind, example)}
                    prefetch={false}
                    className="font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
                  >
                    {example}
                  </Link>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-muted">
              Sample subjects are fictional (or harmless well-known ones) and are always labelled as
              demo data. Values you look up are never shown as live intelligence unless a connected
              provider answered.
            </p>
          </div>
        )}
      </div>
    </>
  );
}
