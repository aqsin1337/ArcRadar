import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ActorForm } from "@/components/threat-intel/actor-form";
import { buttonClasses } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { AccessDenied } from "@/components/ui/states";
import { ApiError } from "@/lib/api/errors";
import { getPageAuthContext } from "@/lib/auth/session";
import { getActor, getLinkOptions, isEntityId } from "@/lib/threat-intel/service";
import type { ActorDetail } from "@/lib/threat-intel/types";

export const metadata: Metadata = { title: "Edit threat actor" };

export default async function EditThreatActorPage({
  params,
}: PageProps<"/threat-actors/[id]/edit">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const { id } = await params;
  if (!isEntityId(id)) notFound();
  if (!auth.permissions.has("threat_intel:write")) {
    return (
      <AccessDenied
        title="You can't edit threat actors"
        description="Editing threat intelligence needs the administrator role."
        action={
          <Link href={`/threat-actors/${id}`} className={buttonClasses({ variant: "secondary" })}>
            Back to the threat actor
          </Link>
        }
      />
    );
  }

  let actor: ActorDetail | null = null;
  try {
    actor = await getActor(auth.supabase, id);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 404)) throw error;
  }
  if (!actor) notFound();

  const options = await getLinkOptions(auth.supabase);
  return (
    <>
      <PageHeader
        title={`Edit ${actor.name}`}
        description="Changes are recorded in the audit log."
      />
      <Card className="max-w-4xl">
        <CardContent>
          <ActorForm mode="edit" actor={actor} options={options} />
        </CardContent>
      </Card>
    </>
  );
}
