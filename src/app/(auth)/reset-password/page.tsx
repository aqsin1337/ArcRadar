import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth/auth-card";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";
import { getPageAuth } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Set a new password" };

/**
 * Landing page of the recovery email. `/auth/callback` has already exchanged the emailed code for a
 * session, so the visitor is signed in here; without a session the link was invalid or used up.
 */
export default async function ResetPasswordPage() {
  if ((await getPageAuth()).status === "signed_out") redirect("/login?error=invalid_link");

  return (
    <AuthCard
      title="Set a new password"
      description="Choose a strong password you don't use anywhere else."
    >
      <ResetPasswordForm />
    </AuthCard>
  );
}
