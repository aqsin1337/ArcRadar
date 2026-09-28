import Link from "next/link";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { CampaignStatusBadge, OriginBadge } from "@/components/ui/domain-badges";
import { SortHeader } from "@/components/ui/sort-header";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { formatDate, formatDateTime } from "@/lib/format";
import type { ListState } from "@/lib/validation/list-url";
import { actorList, campaignList, malwareList, techniqueList } from "@/lib/threat-intel/url";
import type { ActorListItem, CampaignListItem, MalwareListItem } from "@/lib/threat-intel/types";
import type { MitreTechnique } from "@/types/domain";

type Column = { label: string; sort?: string; show?: string };

// Below the container widths in `show`, a column is hidden so the table keeps room for the name; on a
// narrow container (a phone) the badges, including the provenance label, move under the name.

function SeenDate({ iso }: { iso: string | null }) {
  if (!iso) return <span className="text-muted">—</span>;
  return (
    <time dateTime={iso} title={formatDateTime(iso)}>
      {formatDate(iso)}
    </time>
  );
}

const plural = (count: number, one: string, many = `${one}s`) =>
  `${count} ${count === 1 ? one : many}`;

function ListTable({
  caption,
  columns,
  state,
  defaultSort,
  defaultOrder,
  hrefFor,
  children,
}: {
  caption: string;
  columns: Column[];
  state: ListState;
  defaultSort: string;
  defaultOrder: string;
  hrefFor: (state: ListState, overrides: ListState) => string;
  children: ReactNode;
}) {
  const sort = String(state.sort ?? defaultSort);
  const order = String(state.order ?? defaultOrder);
  return (
    <div className="@container">
      <Table caption={caption}>
        <THead>
          <tr>
            {columns.map(({ label, sort: field, show }) =>
              field ? (
                <SortHeader
                  key={label}
                  label={label}
                  field={field}
                  sort={sort}
                  order={order}
                  className={show}
                  hrefFor={(sortField, nextOrder) =>
                    hrefFor(state, { sort: sortField, order: nextOrder, page: 1 })
                  }
                />
              ) : (
                <Th key={label} className={show}>
                  {label}
                </Th>
              ),
            )}
          </tr>
        </THead>
        <TBody>{children}</TBody>
      </Table>
    </div>
  );
}

const NAME_LINK = "text-sm font-medium text-primary [overflow-wrap:anywhere] hover:underline";

export function ActorTable({ items, state }: { items: ActorListItem[]; state: ListState }) {
  return (
    <ListTable
      caption="Threat actors"
      state={state}
      defaultSort="name"
      defaultOrder="asc"
      hrefFor={actorList.href}
      columns={[
        { label: "Threat actor", sort: "name" },
        { label: "Motivation", show: "hidden @2xl:table-cell" },
        { label: "Linked", show: "hidden @3xl:table-cell" },
        { label: "Origin", show: "hidden @3xl:table-cell" },
        { label: "Last seen", sort: "last_seen", show: "hidden @3xl:table-cell" },
      ]}
    >
      {items.map((item) => (
        <Tr key={item.id}>
          <Td className="max-w-lg min-w-48">
            <Link href={`/threat-actors/${item.id}`} className={NAME_LINK}>
              {item.name}
            </Link>
            {item.aliases.length > 0 && (
              <p className="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">
                Also known as {item.aliases.join(", ")}
              </p>
            )}
            <div className="mt-2 @3xl:hidden">
              <OriginBadge origin={item.origin} />
            </div>
          </Td>
          <Td className="hidden text-sm @2xl:table-cell">
            {item.motivation ?? <span className="text-muted">Unknown</span>}
          </Td>
          <Td className="hidden text-xs text-muted @3xl:table-cell">
            {plural(item.counts.malware, "malware family", "malware families")}
            <br />
            {plural(item.counts.campaigns, "campaign")} ·{" "}
            {plural(item.counts.techniques, "technique")}
          </Td>
          <Td className="hidden @3xl:table-cell">
            <OriginBadge origin={item.origin} />
          </Td>
          <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
            <SeenDate iso={item.last_seen} />
          </Td>
        </Tr>
      ))}
    </ListTable>
  );
}

export function CampaignTable({ items, state }: { items: CampaignListItem[]; state: ListState }) {
  return (
    <ListTable
      caption="Campaigns"
      state={state}
      defaultSort="last_seen"
      defaultOrder="desc"
      hrefFor={campaignList.href}
      columns={[
        { label: "Campaign", sort: "name" },
        { label: "Status", sort: "status", show: "hidden @2xl:table-cell" },
        { label: "Linked", show: "hidden @3xl:table-cell" },
        { label: "Origin", show: "hidden @3xl:table-cell" },
        { label: "Last seen", sort: "last_seen", show: "hidden @3xl:table-cell" },
      ]}
    >
      {items.map((item) => (
        <Tr key={item.id}>
          <Td className="max-w-lg min-w-48">
            <Link href={`/campaigns/${item.id}`} className={NAME_LINK}>
              {item.name}
            </Link>
            {item.description && (
              <p className="mt-0.5 line-clamp-2 text-xs text-muted [overflow-wrap:anywhere]">
                {item.description}
              </p>
            )}
            <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
              <CampaignStatusBadge status={item.status} />
              <OriginBadge origin={item.origin} />
            </div>
          </Td>
          <Td className="hidden @2xl:table-cell">
            <CampaignStatusBadge status={item.status} />
          </Td>
          <Td className="hidden text-xs text-muted @3xl:table-cell">
            {plural(item.counts.actors, "threat actor")}
            <br />
            {plural(item.counts.indicators, "indicator")}
          </Td>
          <Td className="hidden @3xl:table-cell">
            <OriginBadge origin={item.origin} />
          </Td>
          <Td className="hidden whitespace-nowrap text-muted @3xl:table-cell">
            <SeenDate iso={item.last_seen} />
          </Td>
        </Tr>
      ))}
    </ListTable>
  );
}

export function MalwareTable({ items, state }: { items: MalwareListItem[]; state: ListState }) {
  return (
    <ListTable
      caption="Malware families"
      state={state}
      defaultSort="name"
      defaultOrder="asc"
      hrefFor={malwareList.href}
      columns={[
        { label: "Malware family", sort: "name" },
        { label: "Type", sort: "malware_type", show: "hidden @2xl:table-cell" },
        { label: "Platforms", show: "hidden @2xl:table-cell" },
        { label: "Linked", show: "hidden @3xl:table-cell" },
        { label: "Origin", show: "hidden @3xl:table-cell" },
      ]}
    >
      {items.map((item) => (
        <Tr key={item.id}>
          <Td className="max-w-lg min-w-48">
            <Link href={`/malware/${item.id}`} className={NAME_LINK}>
              {item.name}
            </Link>
            <div className="mt-2 flex flex-wrap items-center gap-1.5 @2xl:hidden">
              {item.malware_type && <Badge tone="slate">{item.malware_type}</Badge>}
              <OriginBadge origin={item.origin} />
            </div>
          </Td>
          <Td className="hidden text-sm @2xl:table-cell">
            {item.malware_type ?? <span className="text-muted">Unknown</span>}
          </Td>
          <Td className="hidden text-sm @2xl:table-cell">
            {item.platforms.length > 0 ? (
              item.platforms.join(", ")
            ) : (
              <span className="text-muted">—</span>
            )}
          </Td>
          <Td className="hidden text-xs text-muted @3xl:table-cell">
            {plural(item.counts.actors, "threat actor")}
            <br />
            {plural(item.counts.indicators, "indicator")}
          </Td>
          <Td className="hidden @3xl:table-cell">
            <OriginBadge origin={item.origin} />
          </Td>
        </Tr>
      ))}
    </ListTable>
  );
}

export function TechniqueTable({ items, state }: { items: MitreTechnique[]; state: ListState }) {
  return (
    <ListTable
      caption="MITRE ATT&CK techniques"
      state={state}
      defaultSort="id"
      defaultOrder="asc"
      hrefFor={techniqueList.href}
      columns={[
        { label: "Id", sort: "id" },
        { label: "Technique", sort: "name" },
        { label: "Tactics", show: "hidden @2xl:table-cell" },
      ]}
    >
      {items.map((item) => (
        <Tr key={item.id}>
          <Td className="font-mono whitespace-nowrap">
            <Link href={`/mitre/${item.id}`} className={NAME_LINK}>
              {item.id}
            </Link>
          </Td>
          <Td className="max-w-lg min-w-40 text-sm [overflow-wrap:anywhere]">
            {item.name}
            <div className="mt-1.5 flex flex-wrap gap-1.5 @2xl:hidden">
              {item.tactics.map((tactic) => (
                <Badge key={tactic} tone="slate">
                  {tactic}
                </Badge>
              ))}
            </div>
          </Td>
          <Td className="hidden @2xl:table-cell">
            <div className="flex flex-wrap gap-1.5">
              {item.tactics.map((tactic) => (
                <Badge key={tactic} tone="slate">
                  {tactic}
                </Badge>
              ))}
            </div>
          </Td>
        </Tr>
      ))}
    </ListTable>
  );
}
