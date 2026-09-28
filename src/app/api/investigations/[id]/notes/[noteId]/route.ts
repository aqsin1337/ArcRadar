import { protectedRoute } from "@/lib/api/handler";
import { ok } from "@/lib/api/response";
import { parseJsonBody } from "@/lib/api/validate";
import { noteSchema } from "@/lib/investigations/schema";
import { editNote, removeNote } from "@/lib/investigations/service";

export const dynamic = "force-dynamic";

type Params = { id: string; noteId: string };

/** PATCH /api/investigations/:id/notes/:noteId  { body } — only the author may edit a note; status history is read-only (403). */
export const PATCH = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) => {
    const input = await parseJsonBody(request, noteSchema);
    return ok(await editNote(auth, params.id, params.noteId, input, request));
  },
);

/** DELETE /api/investigations/:id/notes/:noteId — the author, or an administrator; status history cannot be deleted (403). */
export const DELETE = protectedRoute<Params>(
  { permissions: ["investigations:write"] },
  async ({ request, auth, params }) =>
    ok(await removeNote(auth, params.id, params.noteId, request)),
);
