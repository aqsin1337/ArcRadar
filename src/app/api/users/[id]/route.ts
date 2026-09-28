import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { updateUserSchema } from "@/lib/users/schema";
import { updateUser } from "@/lib/users/service";

export const dynamic = "force-dynamic";

type Params = { id: string };

/**
 * PATCH /api/users/:id  { role_name?, is_active? }
 * Needs users:manage (admins). Refuses to change the caller's own account, and refuses to leave
 * the workspace with no active administrator.
 */
export const PATCH = protectedRoute<Params>(
  { permissions: ["users:manage"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, updateUserSchema);
    await updateUser(auth, params.id, input, request);
    return ok({ updated: true });
  },
);
