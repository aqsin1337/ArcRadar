import { publicRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { requestPasswordReset } from "@/lib/auth/service";
import { forgotPasswordSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/** POST /api/auth/forgot-password  { email } -> always `sent: true` (no account enumeration). */
export const POST = publicRoute(async ({ request, supabase }) => {
  const { email } = await parseJsonBody(request, forgotPasswordSchema);
  await requestPasswordReset(supabase, email, request);
  return ok({ sent: true });
});
