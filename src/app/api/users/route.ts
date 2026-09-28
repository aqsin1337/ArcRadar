import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { listUsers } from "@/lib/users/service";

export const dynamic = "force-dynamic";

/** GET /api/users — every account, with its role and active status. Needs users:read (admins). */
export const GET = protectedRoute({ permissions: ["users:read"] }, async () =>
  ok(await listUsers()),
);
