import type { Metadata } from "next";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { roleLabel } from "@/types/domain";
import { PageHeader } from "@/components/ui/page-header";
import { TimeText } from "@/components/ui/detail-list";
import { ChangePasswordForm } from "@/components/settings/change-password-form";
import { ProfileForm } from "@/components/settings/profile-form";
import { getPageAuthContext } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Profile" };

export default async function ProfilePage() {
  const auth = await getPageAuthContext();
  if (!auth) return null;

  const { data: profile } = await auth.supabase
    .from("profiles")
    .select("avatar_url, created_at")
    .eq("id", auth.user.id)
    .single();

  return (
    <>
      <PageHeader
        title="Profile"
        description="Your own account. Roles and access are set by an administrator, not from here."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Account</CardTitle>
            <CardDescription>{auth.user.email}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center justify-between gap-3">
              <span className="text-muted">Role</span>
              <Badge tone="brand">{roleLabel(auth.profile.role)}</Badge>
            </div>
            {profile?.created_at && (
              <div className="flex items-center justify-between gap-3">
                <span className="text-muted">Member since</span>
                <TimeText iso={profile.created_at} />
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Edit profile</CardTitle>
            <CardDescription>Your display name and avatar.</CardDescription>
          </CardHeader>
          <CardContent>
            <ProfileForm
              displayName={auth.profile.display_name}
              avatarUrl={profile?.avatar_url ?? null}
            />
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Password</CardTitle>
            <CardDescription>Changing it signs out your other sessions.</CardDescription>
          </CardHeader>
          <CardContent>
            <ChangePasswordForm />
          </CardContent>
        </Card>
      </div>
    </>
  );
}
