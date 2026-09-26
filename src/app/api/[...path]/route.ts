import { apiErrors } from "@/lib/api/errors";
import { fail } from "@/lib/api/response";

// Unknown /api/* paths answer with the JSON envelope instead of the HTML 404 page. Concrete route
// files always win over this catch-all.
function notFound() {
  const error = apiErrors.notFound("No such API endpoint.");
  return fail(error.status, error.code, error.message, undefined, { "Cache-Control": "no-store" });
}

export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;
export const OPTIONS = notFound;
