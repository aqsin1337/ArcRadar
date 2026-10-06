import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { userSubject } from "@/lib/rate-limit/service";
import { createUserSchema } from "@/lib/users/schema";
import { createUser, listUsers } from "@/lib/users/service";

export const dynamic = "force-dynamic";

/** GET /api/users — every account, with its role and active status. Needs users:read (admins). */
export const GET = protectedRoute({ permissions: ["users:read"] }, async () =>
  ok(await listUsers()),
);

/**
 * POST /api/users  { email, password, display_name, role_name }
 * An administrator makes an account for a teammate: active at once, with the chosen role and no
 * confirmation mail. Needs users:manage (admins). `409` when the email already has an account.
 */
export const POST = protectedRoute(
  {
    permissions: ["users:manage"],
    rateLimit: { routeClass: "userCreateByUser", subject: ({ auth }) => userSubject(auth) },
  },
  async ({ request, auth }) => {
    const input = await parseJsonBody(request, createUserSchema);
    return ok(await createUser(auth, input, request), { status: 201 });
  },
);
