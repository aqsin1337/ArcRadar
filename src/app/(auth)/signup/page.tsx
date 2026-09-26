import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth/auth-card";
import { SignupForm } from "@/components/auth/signup-form";
import { getPageAuth } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Create account" };

export default async function SignupPage() {
  if ((await getPageAuth()).status === "ok") redirect("/dashboard");

  return (
    <AuthCard
      title="Create your account"
      description="New accounts start with read-only access."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-primary hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <SignupForm />
    </AuthCard>
  );
}
