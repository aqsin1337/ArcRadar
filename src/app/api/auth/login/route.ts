import { publicRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { login } from "@/lib/auth/service";
import { loginSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/** POST /api/auth/login  { email, password } -> the signed-in user's session info. */
export const POST = publicRoute(async ({ request, supabase }) => {
  const input = await parseJsonBody(request, loginSchema);
  return ok(await login(supabase, input, request));
});
