import { ArrowLeft, ExternalLink } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { RecordChips, ValueChips } from "@/components/threat-intel/linked-records";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DetailRow as Row } from "@/components/ui/detail-list";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getTechnique, parseTechniqueId } from "@/lib/threat-intel/service";
import type { TechniqueDetail } from "@/lib/threat-intel/types";

export default async function TechniquePage({ params }: PageProps<"/mitre/[id]">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { id } = await params;
  if (!parseTechniqueId(id)) notFound();

  let technique: TechniqueDetail | null = null;
  try {
    technique = await getTechnique(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!technique) notFound();

  return (
    <>
      <title>{`${technique.id} ${technique.name} · MITRE ATT&CK · ArcRadar`}</title>

      <Link
        href="/mitre"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
      >
        <ArrowLeft aria-hidden className="size-4" />
        All techniques
      </Link>

      <div className="mb-6 min-w-0 space-y-2">
        <h1
          className="text-xl font-semibold [overflow-wrap:anywhere] sm:text-2xl"
          data-testid="record-title"
        >
          <span className="font-mono">{technique.id}</span> {technique.name}
        </h1>
        <p className="text-sm text-muted">
          MITRE ATT&CK reference data, not intelligence about your environment.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              {technique.description ? (
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                  {technique.description}
                </p>
              ) : (
                <p className="text-sm text-muted">
                  No description is stored here. The ATT&CK page has the full write-up.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat actors known to use it</CardTitle>
            </CardHeader>
            <CardContent>
              <RecordChips
                empty="No threat actor in this workspace is linked to this technique."
                items={technique.actors.map((item) => ({
                  id: item.id,
                  label: item.name,
                  href: `/threat-actors/${item.id}`,
                  origin: item.origin,
                }))}
              />
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="divide-y divide-border">
                <Row label="Id">
                  <span className="font-mono">{technique.id}</span>
                </Row>
                <Row label="Tactics">
                  <ValueChips values={technique.tactics} empty="Not recorded" />
                </Row>
                {technique.url && (
                  <Row label="Reference">
                    <a
                      href={technique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      attack.mitre.org
                      <ExternalLink aria-hidden className="size-3.5" />
                      <span className="sr-only"> (opens in a new tab)</span>
                    </a>
                  </Row>
                )}
              </dl>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
