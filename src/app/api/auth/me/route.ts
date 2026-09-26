import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { toSessionInfo } from "@/lib/auth/context";

export const dynamic = "force-dynamic";

/** GET /api/auth/me -> the signed-in user, their role and permissions. */
export const GET = protectedRoute({}, async ({ auth }) => ok(toSessionInfo(auth)));
