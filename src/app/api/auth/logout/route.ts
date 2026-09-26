import { publicRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { logout } from "@/lib/auth/service";

export const dynamic = "force-dynamic";

/** POST /api/auth/logout -> ends the current session (succeeds even when signed out). */
export const POST = publicRoute(async ({ request, supabase }) => {
  await logout(supabase, request);
  return ok({ signed_out: true });
});
