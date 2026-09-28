import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { noteSchema } from "@/lib/investigations/schema";
import { addNote } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

/** POST /api/investigations/:id/notes  { body } — adds a note as the caller. Needs investigations:write. */
export const POST = protectedRoute<{ id: string }>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, noteSchema);
    return ok(await addNote(auth, params.id, input, request), { status: 201 });
  },
);
