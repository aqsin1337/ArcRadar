import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updatePassword } from "@/lib/auth/service";
import { updatePasswordSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/**
 * POST /api/auth/update-password  { password }
 * For the signed-in user, including the short-lived session created by a recovery email link.
 */
export const POST = protectedRoute({}, async ({ request, auth }) => {
  const { password } = await parseJsonBody(request, updatePasswordSchema);
  await updatePassword(auth, password, request);
  return ok({ updated: true });
});
