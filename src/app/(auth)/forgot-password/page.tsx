import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth/auth-card";
import { ForgotPasswordForm } from "@/components/auth/forgot-password-form";
import { getPageAuth } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Reset password" };

export default async function ForgotPasswordPage() {
  if ((await getPageAuth()).status === "ok") redirect("/dashboard");

  return (
    <AuthCard
      title="Reset your password"
      description="Enter your email and we'll send you a link to set a new password."
      footer={
        <Link href="/login" className="font-medium text-primary hover:underline">
          Back to sign in
        </Link>
      }
    >
      <ForgotPasswordForm />
    </AuthCard>
  );
}
