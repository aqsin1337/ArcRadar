import { Grid3x3 } from "lucide-react";
import type { Metadata } from "next";
import { TechniqueFilters } from "@/components/threat-intel/threat-filters";
import { TechniqueTable } from "@/components/threat-intel/threat-tables";
import { Alert } from "@/components/ui/alert";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { parseTechniqueListParams } from "@/lib/threat-intel/schema";
import { listTactics, listTechniques } from "@/lib/threat-intel/service";
import { techniqueList } from "@/lib/threat-intel/url";

export const metadata: Metadata = { title: "MITRE ATT&CK" };

export default async function MitrePage({ searchParams }: PageProps<"/mitre">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseTechniqueListParams(await searchParams);
  const [{ items, pagination }, tactics] = await Promise.all([
    listTechniques(auth.supabase, query),
    listTactics(auth.supabase),
  ]);

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="The adversary techniques this workspace knows, and which threat actors use them. This is a reference list, not a live feed: it holds the techniques your team has added, not the full ATT&CK matrix."
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}
        <TechniqueFilters state={query} tactics={tactics} />
        <ListResults
          pagination={pagination}
          count={items.length}
          filtered={techniqueList.hasActive(query)}
          noun={["technique", "techniques"]}
          listHref="/mitre"
          hrefForPage={(page) => techniqueList.href(query, { page })}
          empty={{
            icon: Grid3x3,
            title: "No techniques yet",
            description: "No ATT&CK techniques have been added to this workspace.",
          }}
        >
          <TechniqueTable items={items} state={query} />
        </ListResults>
      </div>
    </>
  );
}
