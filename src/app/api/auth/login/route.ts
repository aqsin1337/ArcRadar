import { publicRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { login } from "@/lib/auth/service";
import { ipSubject } from "@/lib/rate-limit/service";
import { loginSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/**
 * POST /api/auth/login  { email, password } -> the signed-in user's session info.
 * Rate-limited by IP (`authByIp`): a defense against credential stuffing by volume, independent
 * of Supabase Auth's own limits.
 */
export const POST = publicRoute(
  async ({ request, supabase }) => {
    const input = await parseJsonBody(request, loginSchema);
    return ok(await login(supabase, input, request));
  },
  { rateLimit: { routeClass: "authByIp", subject: ({ request }) => ipSubject(request) } },
);
