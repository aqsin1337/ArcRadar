import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { aiSettingsPatchSchema, getAiAvailability, setAiAvailability } from "@/lib/ai/service";

export const dynamic = "force-dynamic";

/**
 * GET /api/ai/settings — every AI-capable provider, whether it is configured and enabled, and which
 * one (if any) is active right now. Needs ai:use (administrators hold it too, alongside ai:manage):
 * analysts see why the AI buttons on an alert do or do not work, even though only an administrator
 * can change the choice.
 */
export const GET = protectedRoute({ permissions: ["ai:use"] }, async ({ auth }) =>
  ok(await getAiAvailability(auth.supabase)),
);

/**
 * PATCH /api/ai/settings  { active_provider, active_model }
 * Chooses the active AI provider (or clears it with `null`) and its model name. Needs ai:manage. The
 * provider must already be configured (a server-side key/URL is set) and enabled.
 */
export const PATCH = protectedRoute({ permissions: ["ai:manage"] }, async ({ request, auth }) => {
  const input = await parseJsonBody(request, aiSettingsPatchSchema);
  return ok(await setAiAvailability(auth, input, request));
});
