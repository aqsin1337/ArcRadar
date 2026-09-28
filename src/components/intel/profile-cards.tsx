import Link from "next/link";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfidenceMeter } from "@/components/ui/confidence-meter";
import { DetailRow, TimeText } from "@/components/ui/detail-list";
import { OriginBadge, VerdictBadge } from "@/components/ui/domain-badges";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { formatBytes } from "@/lib/format";
import { intelHref } from "@/lib/intel/constants";
import type {
  DomainProfile,
  HashProfile,
  IntelKind,
  IntelProfile,
  IpProfile,
  ProviderResult,
  UrlProfile,
} from "@/lib/intel/types";
import { DetectionBar } from "./detection-bar";

const MISSING = <span className="text-muted">—</span>;

function Row({ label, children }: { label: string; children?: ReactNode }) {
  const empty =
    children === null || children === undefined || children === false || children === "";
  return <DetailRow label={label}>{empty ? MISSING : children}</DetailRow>;
}

function Heading({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">{children}</h3>
  );
}

function Chips({ items }: { items: (string | number)[] }) {
  if (items.length === 0) return MISSING;
  return (
    <span className="inline-flex flex-wrap justify-end gap-1.5">
      {items.map((item) => (
        <Badge key={item} tone="slate">
          {item}
        </Badge>
      ))}
    </span>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[13px] [overflow-wrap:anywhere]">{children}</span>;
}

/** Values that have a lookup page of their own link to it. Prefetching is off: opening the page is the lookup. */
function LookupLinks({ kind, values }: { kind: IntelKind; values: string[] }) {
  if (values.length === 0) return MISSING;
  return (
    <ul className="space-y-0.5">
      {values.map((value) => (
        <li key={value}>
          <Link
            href={intelHref(kind, value)}
            prefetch={false}
            className="font-mono text-[13px] [overflow-wrap:anywhere] text-primary hover:underline"
          >
            {value}
          </Link>
        </li>
      ))}
    </ul>
  );
}

function MonoList({ values }: { values: string[] }) {
  if (values.length === 0) return MISSING;
  return (
    <ul className="space-y-0.5">
      {values.map((value) => (
        <li key={value}>
          <Mono>{value}</Mono>
        </li>
      ))}
    </ul>
  );
}

const when = (iso: string | null) => (iso ? <TimeText iso={iso} /> : null);

/** The verdict a provider reached, the engine counts behind it and the engines that flagged the subject. */
function Assessment({ profile }: { profile: IntelProfile }) {
  const { reputation, detections, findings, tags } = profile;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <VerdictBadge verdict={reputation.verdict} />
        {reputation.confidence !== null && (
          <span className="inline-flex items-center gap-2 text-sm text-muted">
            Confidence <ConfidenceMeter value={reputation.confidence} />
          </span>
        )}
      </div>
      {reputation.summary && <p className="text-sm leading-relaxed">{reputation.summary}</p>}
      {detections && <DetectionBar detections={detections} />}
      {findings.length > 0 && (
        <details className="rounded-lg border border-border">
          <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
            Engines that flagged it ({findings.length})
          </summary>
          <ul className="divide-y divide-border border-t border-border text-sm">
            {findings.map((finding, index) => (
              <li
                key={`${finding.engine}-${index}`}
                className="flex justify-between gap-3 px-3 py-1.5"
              >
                <span>{finding.engine}</span>
                <span className="text-right text-muted">{finding.result ?? finding.category}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {tags.map((tag) => (
            <Badge key={tag} tone="slate">
              {tag}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function IpFacts({ profile }: { profile: IpProfile }) {
  return (
    <dl className="divide-y divide-border">
      <Row label="Version">{`IPv${profile.version}`}</Row>
      <Row label="Network">{profile.network && <Mono>{profile.network}</Mono>}</Row>
      <Row label="ASN">{profile.asn !== null && `AS${profile.asn}`}</Row>
      <Row label="Organization">{profile.organization}</Row>
      {profile.isp && profile.isp !== profile.organization && <Row label="ISP">{profile.isp}</Row>}
      <Row label="Usage">{profile.usage_type}</Row>
      <Row label="Country">{profile.country}</Row>
      <Row label="Region">{profile.region}</Row>
      <Row label="City">{profile.city}</Row>
      <Row label="Hostnames (reverse DNS)">
        <MonoList values={profile.hostnames} />
      </Row>
      <Row label="Open ports">
        <Chips items={profile.open_ports} />
      </Row>
      <Row label="Related domains">
        <LookupLinks kind="domain" values={profile.related_domains} />
      </Row>
      {profile.report_count !== null && (
        <Row label="Abuse reports">
          {profile.report_count}
          {profile.last_reported_at && (
            <span className="font-normal text-muted"> · last {when(profile.last_reported_at)}</span>
          )}
        </Row>
      )}
      <Row label="Last analysed">{when(profile.last_analysed_at)}</Row>
    </dl>
  );
}

function DomainFacts({ profile }: { profile: DomainProfile }) {
  return (
    <div className="space-y-4">
      <dl className="divide-y divide-border">
        <Row label="Registrar">{profile.registrar}</Row>
        <Row label="Registered">{when(profile.created_at)}</Row>
        <Row label="Updated">{when(profile.updated_at)}</Row>
        <Row label="Expires">{when(profile.expires_at)}</Row>
        <Row label="Nameservers">
          <MonoList values={profile.nameservers} />
        </Row>
        <Row label="Related IPs">
          <LookupLinks kind="ip" values={profile.related_ips} />
        </Row>
        <Row label="Categories">
          <Chips items={profile.categories} />
        </Row>
        <Row label="Last analysed">{when(profile.last_analysed_at)}</Row>
      </dl>
      {profile.dns_records.length > 0 && (
        <div>
          <Heading>DNS records</Heading>
          <Table caption="DNS records">
            <THead>
              <tr>
                <Th>Type</Th>
                <Th>Value</Th>
                <Th className="text-right">TTL</Th>
              </tr>
            </THead>
            <TBody>
              {profile.dns_records.map((record, index) => (
                <Tr key={`${record.type}-${record.value}-${index}`}>
                  <Td className="w-16 whitespace-nowrap">{record.type}</Td>
                  <Td>
                    <Mono>{record.value}</Mono>
                  </Td>
                  <Td className="text-right whitespace-nowrap text-muted tabular-nums">
                    {record.ttl ?? "—"}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </div>
      )}
    </div>
  );
}

function UrlFacts({ profile }: { profile: UrlProfile }) {
  return (
    <div className="space-y-4">
      <dl className="divide-y divide-border">
        <Row label="Domain">
          <LookupLinks kind="domain" values={[profile.host]} />
        </Row>
        <Row label="Final URL">{profile.final_url && <Mono>{profile.final_url}</Mono>}</Row>
        <Row label="HTTP status">{profile.http_status}</Row>
        <Row label="Page title">{profile.title}</Row>
        <Row label="Categories">
          <Chips items={profile.categories} />
        </Row>
        <Row label="First submitted">{when(profile.first_submitted_at)}</Row>
        <Row label="Last analysed">{when(profile.last_analysed_at)}</Row>
      </dl>
      {profile.redirect_chain.length > 1 && (
        <div>
          <Heading>Redirects</Heading>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {profile.redirect_chain.map((step) => (
              <li key={step}>
                <Mono>{step}</Mono>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

const HASH_LABELS = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" } as const;

function HashFacts({ profile }: { profile: HashProfile }) {
  return (
    <dl className="divide-y divide-border">
      <Row label="Hash type">{HASH_LABELS[profile.hash_type]}</Row>
      {(["md5", "sha1", "sha256"] as const).map((type) => (
        <Row key={type} label={HASH_LABELS[type]}>
          {profile.hashes[type] && <Mono>{profile.hashes[type]}</Mono>}
        </Row>
      ))}
      <Row label="Malware family">
        <Chips items={profile.malware_families} />
      </Row>
      <Row label="File name">{profile.file_name}</Row>
      {profile.file_names.length > 1 && (
        <Row label="Also seen as">
          <MonoList values={profile.file_names.filter((name) => name !== profile.file_name)} />
        </Row>
      )}
      <Row label="File type">{profile.file_type}</Row>
      <Row label="Size">{profile.file_size !== null && formatBytes(profile.file_size)}</Row>
      <Row label="First submitted">{when(profile.first_submitted_at)}</Row>
      <Row label="Last analysed">{when(profile.last_analysed_at)}</Row>
    </dl>
  );
}

function Facts({ profile }: { profile: IntelProfile }) {
  switch (profile.kind) {
    case "ip":
      return <IpFacts profile={profile} />;
    case "domain":
      return <DomainFacts profile={profile} />;
    case "url":
      return <UrlFacts profile={profile} />;
    case "hash":
      return <HashFacts profile={profile} />;
  }
}

/**
 * One provider's answer, with its own provenance label: nothing from a demo provider and a live
 * provider is ever blended into one card.
 */
export function ProfileCard({ result }: { result: ProviderResult }) {
  const { provider, profile } = result;
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle>{provider.name}</CardTitle>
          <OriginBadge origin={provider.origin} />
        </div>
        <CardDescription>
          {provider.origin === "demo" ? (
            "Sample data from the built-in demo dataset. This is not a live lookup."
          ) : (
            <>
              Retrieved <TimeText iso={profile.retrieved_at} />
            </>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <Assessment profile={profile} />
        <Facts profile={profile} />
      </CardContent>
    </Card>
  );
}
