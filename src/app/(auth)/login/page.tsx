import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AuthCard } from "@/components/auth/auth-card";
import { LoginForm, type LoginNotice } from "@/components/auth/login-form";
import { safeRedirectPath } from "@/lib/auth/redirect";
import { getPageAuth } from "@/lib/auth/session";
import { getDemoLogins } from "@/lib/demo-accounts";
import { firstParam } from "@/lib/search-params";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const params = await searchParams;
  // `next` comes from the URL, so it is validated here and again before the client navigates.
  const next = safeRedirectPath(firstParam(params.next), "/dashboard");

  // Verified against the auth server, not just the cookie, so a stale cookie cannot cause a loop.
  const auth = await getPageAuth();
  if (auth.status === "ok") redirect(next);

  const error = firstParam(params.error);
  const notice: LoginNotice =
    error === "invalid_link" || error === "callback_failed" ? error : null;

  return (
    <AuthCard
      title="Sign in"
      description="Welcome back. Enter your details to continue to ArcRadar."
      footer={
        <>
          New to ArcRadar?{" "}
          <Link href="/signup" className="font-medium text-primary hover:underline">
            Create an account
          </Link>
        </>
      }
    >
      <LoginForm next={next} notice={notice} demo={getDemoLogins()} />
    </AuthCard>
  );
}
