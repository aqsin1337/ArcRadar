import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { toSessionInfo } from "@/lib/auth/context";
import { updateProfile } from "@/lib/auth/service";
import { parseJsonBody } from "@/lib/api/validate";
import { updateProfileSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/** GET /api/auth/me -> the signed-in user, their role and permissions. */
export const GET = protectedRoute({}, async ({ auth }) => ok(toSessionInfo(auth)));

/** PATCH /api/auth/me  { display_name?, avatar_url? } -> the caller's own profile, updated. */
export const PATCH = protectedRoute({}, async ({ request, auth }) => {
  const input = await parseJsonBody(request, updateProfileSchema);
  return ok(await updateProfile(auth, input, request));
});
