import { Badge, type Tone } from "@/components/ui/badge";
import { OriginBadge } from "@/components/ui/domain-badges";
import { formatDateTime, formatRelative } from "@/lib/format";
import type { SourceCard, SourceStatus } from "@/lib/telemetry/health";

const STATUS: Record<SourceStatus, { label: string; tone: Tone; note: string }> = {
  receiving: {
    label: "Receiving",
    tone: "green",
    note: "Something arrived in the last 15 minutes.",
  },
  quiet: { label: "Quiet", tone: "amber", note: "Nothing has arrived for a while." },
  never: { label: "No events yet", tone: "slate", note: "Nothing has arrived from this source." },
  demo: { label: "Demo feed", tone: "violet", note: "Sample data, not a live connection." },
};

/**
 * One card per telemetry source: what ArcRadar can honestly say, which is when something last
 * arrived. It cannot see the sensor itself, so it never says "connected" or "healthy".
 */
export function SourceCards({ cards, now }: { cards: SourceCard[]; now: Date }) {
  return (
    <ul aria-label="Telemetry sources" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {cards.map((card) => {
        const status = STATUS[card.status];
        return (
          <li
            key={`${card.id}-${card.origin ?? "none"}`}
            className="min-w-0 space-y-3 rounded-xl border border-border bg-surface p-4"
            data-testid="source-card"
            data-source={card.id}
            data-status={card.status}
          >
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold [overflow-wrap:anywhere]">{card.name}</h3>
              {card.origin && <OriginBadge origin={card.origin} />}
              <span className="ml-auto">
                <Badge tone={status.tone} dot>
                  {status.label}
                </Badge>
              </span>
            </div>

            <p className="text-sm text-muted">
              {card.last_received_at ? (
                <>
                  Last received{" "}
                  <time
                    dateTime={card.last_received_at}
                    title={formatDateTime(card.last_received_at)}
                    className="font-medium text-foreground"
                  >
                    {formatRelative(card.last_received_at, now)}
                  </time>
                  {card.status === "demo" ? ". Sample data, not a live connection." : "."}
                </>
              ) : (
                status.note
              )}
            </p>

            {card.last_event_at && (
              <p className="text-xs text-muted">
                The latest event happened{" "}
                <time dateTime={card.last_event_at} title={card.last_event_at}>
                  {formatDateTime(card.last_event_at)}
                </time>
                .
              </p>
            )}

            <dl className="grid grid-cols-4 gap-2 border-t border-border pt-3 text-center">
              {[
                ["Events, 24 h", card.events_24h],
                ["Events", card.events_total],
                ["Alerts", card.alerts_total],
                ["Assets", card.assets_total],
              ].map(([label, value]) => (
                <div key={label} className="min-w-0">
                  <dd className="text-lg font-semibold tabular-nums">{value}</dd>
                  <dt className="text-[11px] leading-tight text-muted">{label}</dt>
                </div>
              ))}
            </dl>
          </li>
        );
      })}
    </ul>
  );
}
