import { ArrowLeft, ArrowRight, Plus } from "lucide-react";
import Link from "next/link";
import { TagChips } from "@/components/indicators/tag-chips";
import { Badge } from "@/components/ui/badge";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfidenceMeter } from "@/components/ui/confidence-meter";
import { DetailRow, TimeText } from "@/components/ui/detail-list";
import {
  IndicatorStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
} from "@/components/ui/domain-badges";
import { INDICATOR_TYPE_SHORT_LABELS, RELATIONSHIP_VERBS } from "@/lib/indicators/constants";
import { INTEL_SUBJECT_LABELS } from "@/lib/intel/constants";
import type { LookupResult } from "@/lib/intel/service";
import type { TimelineEntry } from "@/lib/intel/timeline";
import type { IndicatorRelationship, LinkedEntity } from "@/lib/indicators/types";

function OtherIndicator({ link }: { link: IndicatorRelationship }) {
  return (
    <Link
      href={`/indicators/${link.other.id}`}
      className="font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
    >
      {link.other.value}
    </Link>
  );
}

function Linked({
  title,
  items,
  basePath,
}: {
  title: string;
  items: LinkedEntity[];
  basePath: string;
}) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <h3 className="text-xs font-semibold tracking-wide text-muted uppercase">{title}</h3>
      <ul className="flex flex-wrap gap-x-3 gap-y-1">
        {items.map((item) => (
          <li key={item.id} className="inline-flex items-center gap-1.5 text-sm">
            <Link
              href={`${basePath}/${item.id}`}
              className="font-medium text-primary hover:underline"
            >
              {item.name}
            </Link>
            <OriginBadge origin={item.origin} />
          </li>
        ))}
      </ul>
    </div>
  );
}

/** What this workspace already knows about the subject: its indicator, or a way to start tracking it. */
export function WorkspaceCard({ result, canAdd }: { result: LookupResult; canAdd: boolean }) {
  const { indicator } = result.local;
  const addHref = `/indicators/new?type=${result.indicator_type}&value=${encodeURIComponent(result.value)}`;

  return (
    <Card>
      <CardHeader>
        <CardTitle>In your workspace</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {indicator ? (
          <>
            {(result.recorded === "created" || result.recorded === "updated") && (
              <p className="text-sm text-muted">
                {result.recorded === "created"
                  ? "Added to your indicators automatically from this lookup."
                  : "Refreshed from this lookup."}
              </p>
            )}
            <dl className="divide-y divide-border">
              <DetailRow label="Verdict">
                <VerdictBadge verdict={indicator.verdict} />
              </DetailRow>
              <DetailRow label="Severity">
                <SeverityBadge severity={indicator.severity} />
              </DetailRow>
              <DetailRow label="Confidence">
                <ConfidenceMeter value={indicator.confidence} />
              </DetailRow>
              <DetailRow label="Status">
                <IndicatorStatusBadge status={indicator.status} />
              </DetailRow>
              <DetailRow label="Origin">
                <OriginBadge origin={indicator.origin} />
              </DetailRow>
            </dl>
            {indicator.tags.length > 0 && <TagChips tags={indicator.tags} />}
            <Linked
              title="Threat actors"
              items={indicator.threat_actors}
              basePath="/threat-actors"
            />
            <Linked title="Campaigns" items={indicator.campaigns} basePath="/campaigns" />
            <Linked title="Malware" items={indicator.malware} basePath="/malware" />
            <Link
              href={`/indicators/${indicator.id}`}
              className={buttonClasses({ variant: "secondary", className: "w-full" })}
            >
              Open indicator
            </Link>
          </>
        ) : (
          <>
            <p className="text-sm text-muted">
              This {INTEL_SUBJECT_LABELS[result.kind]} is not tracked as an indicator in your
              workspace.
            </p>
            {canAdd ? (
              <Link href={addHref} className={buttonClasses({ className: "w-full" })}>
                <Plus aria-hidden className="size-4" />
                Add as indicator
              </Link>
            ) : (
              <p className="text-sm text-muted">Analysts and administrators can add it.</p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** Indicators connected to the subject: explicit relationships, and others that mention it. */
export function RelatedCard({ result }: { result: LookupResult }) {
  const links = result.local.indicator?.relationships ?? [];
  const mentions = result.local.related;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Related indicators</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {links.length === 0 && mentions.length === 0 && (
          <p className="text-sm text-muted">No related indicators in your workspace.</p>
        )}

        {links.length > 0 && (
          <ul className="divide-y divide-border">
            {links.map((link) => (
              <li
                key={link.id}
                className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2 text-sm first:pt-0"
              >
                {link.direction === "outgoing" ? (
                  <ArrowRight aria-hidden className="size-4 shrink-0 text-muted" />
                ) : (
                  <ArrowLeft aria-hidden className="size-4 shrink-0 text-muted" />
                )}
                {link.direction === "outgoing" ? (
                  <>
                    <span className="text-muted">{RELATIONSHIP_VERBS[link.relationship]}</span>
                    <OtherIndicator link={link} />
                  </>
                ) : (
                  <>
                    <OtherIndicator link={link} />
                    <span className="text-muted">{RELATIONSHIP_VERBS[link.relationship]} this</span>
                  </>
                )}
                <Badge tone="slate" className="ml-auto">
                  {INDICATOR_TYPE_SHORT_LABELS[link.other.type]}
                </Badge>
              </li>
            ))}
          </ul>
        )}

        {mentions.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold tracking-wide text-muted uppercase">
              Also mentioning it
            </h3>
            <ul className="divide-y divide-border">
              {mentions.map((item) => (
                <li
                  key={item.id}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2 text-sm first:pt-0"
                >
                  <Link
                    href={`/indicators/${item.id}`}
                    className="font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
                  >
                    {item.value}
                  </Link>
                  <span className="ml-auto inline-flex items-center gap-1.5">
                    <Badge tone="slate">{INDICATOR_TYPE_SHORT_LABELS[item.type]}</Badge>
                    <VerdictBadge verdict={item.verdict} />
                    <OriginBadge origin={item.origin} />
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

const KIND_LABELS: Record<TimelineEntry["kind"], string> = {
  first_seen: "Sighting",
  last_seen: "Sighting",
  event: "Event",
  alert: "Alert",
  investigation: "Investigation",
};

/** Sightings, events, alerts and investigations tied to the tracked indicator, newest first. */
export function TimelineCard({ entries, tracked }: { entries: TimelineEntry[]; tracked: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Timeline</CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-muted">
            {tracked
              ? "Nothing has been recorded for this indicator yet."
              : "There is no history until the subject is tracked as an indicator."}
          </p>
        ) : (
          <ol className="space-y-4 border-l border-border pl-4">
            {entries.map((entry, index) => (
              <li key={`${entry.kind}-${entry.at}-${index}`} className="relative space-y-1">
                <span
                  aria-hidden
                  className="absolute top-1.5 -left-[21px] size-2 rounded-full border border-border bg-surface-2"
                />
                <p className="text-xs text-muted">
                  <span className="sr-only">{KIND_LABELS[entry.kind]}: </span>
                  <TimeText iso={entry.at} />
                </p>
                <p className="text-sm font-medium [overflow-wrap:anywhere]">
                  {entry.href ? (
                    <Link href={entry.href} className="text-primary hover:underline">
                      {entry.title}
                    </Link>
                  ) : (
                    entry.title
                  )}
                </p>
                <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted">
                  {entry.detail && <span>{entry.detail}</span>}
                  {entry.severity && <SeverityBadge severity={entry.severity} />}
                  {entry.origin === "demo" && <OriginBadge origin="demo" />}
                </div>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
