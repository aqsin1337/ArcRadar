import { Grid3x3 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { AttackMatrix } from "@/components/mitre/attack-matrix";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied, EmptyState } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { getMatrix } from "@/lib/mitre/service";

export const metadata: Metadata = { title: "MITRE ATT&CK" };

const flag = (value: string | string[] | undefined) => value === "1";

export default async function MitrePage({ searchParams }: PageProps<"/mitre">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const params = await searchParams;
  const observedOnly = flag(params.observed);
  const showSubtechniques = flag(params.sub);
  const matrix = await getMatrix(auth.supabase, { observedOnly });
  const { observed_techniques, total_techniques } = matrix.summary;

  const link = (next: { observed?: boolean; sub?: boolean }) => {
    const query = new URLSearchParams();
    if (next.observed ?? observedOnly) query.set("observed", "1");
    if (next.sub ?? showSubtechniques) query.set("sub", "1");
    const text = query.toString();
    return text ? `/mitre?${text}` : "/mitre";
  };

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="The attack techniques your alerts have pointed at, laid out by tactic (the order of an attack, left to right). A colored technique was named by an alert here; click it to see those alerts."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link
              href={link({ observed: !observedOnly })}
              aria-current={observedOnly ? "true" : undefined}
              className={buttonClasses({ variant: observedOnly ? "primary" : "secondary" })}
            >
              Only what was seen
            </Link>
            <Link
              href={link({ sub: !showSubtechniques })}
              aria-current={showSubtechniques ? "true" : undefined}
              className={buttonClasses({ variant: showSubtechniques ? "primary" : "secondary" })}
            >
              Sub-techniques
            </Link>
          </div>
        }
      />

      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span aria-live="polite">
            {observed_techniques === 0
              ? "No alert has named a technique yet."
              : `${observed_techniques} ${observed_techniques === 1 ? "technique" : "techniques"} seen in your alerts, out of ${total_techniques} in the catalog.`}
          </span>
          <span className="text-muted">Worst severity:</span>
          <Badge tone="red">High or critical</Badge>
          <Badge tone="orange">Medium</Badge>
          <Badge tone="blue">Low or info</Badge>
        </div>

        {matrix.tactics.length === 0 ? (
          <EmptyState
            icon={Grid3x3}
            title={observedOnly ? "Nothing seen yet" : "The ATT&CK catalog is empty"}
            description={
              observedOnly
                ? "When a sensor alert names an ATT&CK technique, it appears here."
                : "Load the catalog with npm run import:mitre (see docs/DEPLOYMENT.md)."
            }
            action={
              observedOnly ? (
                <Link href={link({ observed: false })} className={buttonClasses()}>
                  Show the whole matrix
                </Link>
              ) : undefined
            }
          />
        ) : (
          <AttackMatrix matrix={matrix} showSubtechniques={showSubtechniques} />
        )}
      </div>
    </>
  );
}
