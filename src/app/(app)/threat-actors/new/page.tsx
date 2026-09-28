import type { Metadata } from "next";
import Link from "next/link";
import { ActorForm } from "@/components/threat-intel/actor-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { getPageAuthContext } from "@/lib/auth/session";
import { getLinkOptions } from "@/lib/threat-intel/service";

export const metadata: Metadata = { title: "New threat actor" };

export default async function NewThreatActorPage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("threat_intel:write")) {
    return (
      <AccessDenied
        title="You can't add threat actors"
        description="Adding threat intelligence needs the administrator role. You can still browse and search it."
        action={
          <Link href="/threat-actors" className={buttonClasses({ variant: "secondary" })}>
            Back to threat actors
          </Link>
        }
      />
    );
  }

  const options = await getLinkOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title="New threat actor"
        description="Add a profile. It is saved as local data, written by your team and not verified by an external provider."
      />
      <Card className="max-w-4xl">
        <CardContent>
          <ActorForm mode="create" options={options} />
        </CardContent>
      </Card>
    </>
  );
}
