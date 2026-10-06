import { Activity } from "lucide-react";
import type { Metadata } from "next";
import { AssetTable } from "@/components/telemetry/asset-table";
import { EventFilters } from "@/components/telemetry/event-filters";
import { EventTable } from "@/components/telemetry/event-table";
import { SourceCards } from "@/components/telemetry/source-cards";
import { Alert } from "@/components/ui/alert";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { assetListQuerySchema, parseEventListParams } from "@/lib/telemetry/schema";
import { getSourceCards, listAssets, listEvents } from "@/lib/telemetry/service";
import { eventList } from "@/lib/telemetry/url";

export const metadata: Metadata = { title: "Telemetry" };

const ASSETS_SHOWN = 25;

export default async function TelemetryPage({ searchParams }: PageProps<"/telemetry">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("events:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseEventListParams(await searchParams);
  const now = new Date();
  const [cards, assets, events] = await Promise.all([
    getSourceCards(auth.supabase, now),
    listAssets(auth.supabase, assetListQuerySchema.parse({ page_size: ASSETS_SHOWN })),
    listEvents(auth.supabase, query),
  ]);
  const sources = [...new Set(cards.map((card) => card.id))].sort();

  return (
    <>
      <PageHeader
        title="Telemetry"
        description="What sensors send to ArcRadar: when each source last delivered something, the machines it comes from and the latest events. Every record shows where it came from."
      />

      <div className="space-y-8">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <section aria-labelledby="sources-heading" className="space-y-3">
          <h2 id="sources-heading" className="text-base font-semibold">
            Sources
          </h2>
          <SourceCards cards={cards} now={now} />
          <p className="text-xs text-muted">
            ArcRadar only sees what arrives, so a source is shown as receiving or quiet, never as
            connected. A Wazuh Manager that is switched off simply goes quiet.
          </p>
        </section>

        {/* No landmark label here: the table below is already a region named "Assets". */}
        <section className="space-y-3">
          <h2 className="text-base font-semibold">Assets</h2>
          {assets.items.length === 0 ? (
            <p className="text-sm text-muted">
              No machine has reported yet. An asset appears when an alert names its agent.
            </p>
          ) : (
            <>
              <AssetTable items={assets.items} />
              {assets.pagination.total > assets.items.length && (
                <p className="text-xs text-muted">
                  Showing the {assets.items.length} most recently seen of {assets.pagination.total}{" "}
                  assets.
                </p>
              )}
            </>
          )}
        </section>

        <section id="events" className="scroll-mt-20 space-y-3">
          <h2 className="text-base font-semibold">Events</h2>
          <EventFilters state={query} sources={sources} />
          <ListResults
            pagination={events.pagination}
            count={events.items.length}
            filtered={eventList.hasActive(query)}
            noun={["event", "events"]}
            listHref="/telemetry#events"
            hrefForPage={(page) => `${eventList.href(query, { page })}#events`}
            empty={{
              icon: Activity,
              title: "No events yet",
              description:
                "Events appear here when a sensor delivers them. Point a Wazuh Manager or a Splunk server at ArcRadar to start.",
            }}
          >
            <EventTable items={events.items} state={query} />
          </ListResults>
        </section>
      </div>
    </>
  );
}
