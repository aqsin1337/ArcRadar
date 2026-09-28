import { publicRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { signup } from "@/lib/auth/service";
import { ipSubject } from "@/lib/rate-limit/service";
import { signupSchema } from "@/lib/validation/auth";

export const dynamic = "force-dynamic";

/**
 * POST /api/auth/signup  { email, password, display_name? }
 * Same 201 response whether or not the email is already registered; the caller must sign in next.
 * Rate-limited by IP (`authByIp`): bulk account creation is a form of abuse even without enumeration.
 */
export const POST = publicRoute(
  async ({ request, supabase }) => {
    const input = await parseJsonBody(request, signupSchema);
    await signup(supabase, input, request);
    return ok({ registered: true }, { status: 201 });
  },
  { rateLimit: { routeClass: "authByIp", subject: ({ request }) => ipSubject(request) } },
);
