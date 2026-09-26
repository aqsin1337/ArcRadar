import { logError } from "@/lib/log";
import { ApiError, apiErrors } from "./errors";

type SupabaseErrorLike = { code?: string; message: string; details?: string | null };

/**
 * Maps a PostgREST / Postgres error to a client-safe ApiError. Expected failures (RLS denial,
 * unique violation, bad input) become 4xx; everything else is logged and reported as a generic 500
 * so schema details never reach the client.
 */
export function toApiError(error: SupabaseErrorLike): ApiError {
  switch (error.code) {
    case "PGRST116": // .single() / .maybeSingle() matched no row
    case "P0002": // no_data_found, raised by our SQL functions for a missing record
      return apiErrors.notFound();
    case "PGRST301": // JWT expired / invalid
    case "PGRST303":
      return apiErrors.unauthenticated("Your session is no longer valid.");
    case "42501": // insufficient_privilege (RLS or column grant)
      return apiErrors.forbidden();
    case "23505": // unique_violation
      return apiErrors.conflict("A record with these values already exists.");
    case "23503": // foreign_key_violation
      return apiErrors.conflict("The record refers to, or is still used by, another record.");
    case "23502": // not_null_violation
    case "23514": // check_violation
    case "22P02": // invalid_text_representation (for example a malformed uuid)
    case "22001": // string_data_right_truncation
    case "22003": // numeric_value_out_of_range
    case "22007": // invalid_datetime_format
    case "22008": // datetime_field_overflow
      return apiErrors.validation(undefined, "The data violates a database constraint.");
    default:
      logError("supabase.unexpected_error", new Error(error.message), { code: error.code });
      return apiErrors.internal();
  }
}

/** Returns `data` or throws the mapped ApiError. Use in repositories around every query. */
export function unwrap<T>(result: { data: T; error: SupabaseErrorLike | null }): T {
  if (result.error) throw toApiError(result.error);
  return result.data;
}
