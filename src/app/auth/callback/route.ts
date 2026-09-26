import { NextResponse, type NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/audit/write";
import { safeRedirectPath } from "@/lib/auth/redirect";
import { logError } from "@/lib/log";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/**
 * Landing point of the links in Supabase Auth emails (email confirmation, password recovery).
 * Exchanges the one-time `code` for a session cookie, then redirects to `next` (same-site paths
 * only). The recovery flow uses `?next=/reset-password`; the page itself arrives with the frontend.
 */
export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const code = searchParams.get("code");
  const next = safeRedirectPath(searchParams.get("next"));

  const redirect = (path: string) => {
    const response = NextResponse.redirect(new URL(path, request.url));
    response.headers.set("Cache-Control", "no-store");
    return response;
  };

  if (!code) return redirect("/login?error=invalid_link");

  try {
    const supabase = await createClient();
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error || !data.user) return redirect("/login?error=invalid_link");

    await writeAuditLog(
      {
        action: "auth.email_link_session",
        userId: data.user.id,
        entityType: "user",
        entityId: data.user.id,
        metadata: { next },
      },
      request,
    );
    return redirect(next);
  } catch (error) {
    logError("auth.callback_failed", error);
    return redirect("/login?error=callback_failed");
  }
}
