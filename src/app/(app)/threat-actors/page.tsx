import { Plus, Skull } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { ActorFilters } from "@/components/threat-intel/threat-filters";
import { ActorTable } from "@/components/threat-intel/threat-tables";
import { Alert } from "@/components/ui/alert";
import { buttonClasses } from "@/components/ui/button";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseActorListParams } from "@/lib/threat-intel/schema";
import { listActors } from "@/lib/threat-intel/service";
import { actorList } from "@/lib/threat-intel/url";

export const metadata: Metadata = { title: "Threat actors" };

export default async function ThreatActorsPage({ searchParams }: PageProps<"/threat-actors">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseActorListParams(await searchParams);
  const { items, pagination } = await listActors(auth.supabase, query);
  const canWrite = auth.permissions.has("threat_intel:write");

  const newActor = canWrite && (
    <Link href="/threat-actors/new" className={buttonClasses()}>
      <Plus aria-hidden className="size-4" />
      New threat actor
    </Link>
  );

  return (
    <>
      <PageHeader
        title="Threat actors"
        description="Groups and operators, with the malware, campaigns and techniques linked to them. Every profile shows where it came from."
        actions={newActor}
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}
        <ActorFilters state={query} />
        <ListResults
          pagination={pagination}
          count={items.length}
          filtered={actorList.hasActive(query)}
          noun={["threat actor", "threat actors"]}
          listHref="/threat-actors"
          hrefForPage={(page) => actorList.href(query, { page })}
          empty={{
            icon: Skull,
            title: "No threat actors yet",
            description: canWrite
              ? "Add a profile when you start tracking a group."
              : "No profiles have been added yet.",
            action: newActor || undefined,
          }}
        >
          <ActorTable items={items} state={query} />
        </ListResults>
      </div>
    </>
  );
}
