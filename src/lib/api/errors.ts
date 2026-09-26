export type ApiErrorCode =
  | "BAD_REQUEST"
  | "UNAUTHENTICATED"
  | "INVALID_CREDENTIALS"
  | "EMAIL_NOT_CONFIRMED"
  | "FORBIDDEN"
  | "ACCOUNT_DISABLED"
  | "NOT_FOUND"
  | "METHOD_NOT_ALLOWED"
  | "CONFLICT"
  | "PAYLOAD_TOO_LARGE"
  | "UNSUPPORTED_MEDIA_TYPE"
  | "VALIDATION_ERROR"
  | "RATE_LIMITED"
  | "INTERNAL_ERROR"
  | "DEPENDENCY_UNAVAILABLE";

/**
 * An error that is safe to show to the client: `message` and `details` are written for callers, so
 * never put secrets, SQL or stack traces in them. Anything that is not an ApiError is reported as
 * a generic 500 by the route wrapper.
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiErrorCode,
    message: string,
    readonly details?: unknown,
    readonly headers?: Record<string, string>,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export const apiErrors = {
  badRequest: (message = "The request is malformed.", details?: unknown) =>
    new ApiError(400, "BAD_REQUEST", message, details),
  unauthenticated: (message = "Authentication is required.") =>
    new ApiError(401, "UNAUTHENTICATED", message),
  invalidCredentials: () => new ApiError(401, "INVALID_CREDENTIALS", "Invalid email or password."),
  emailNotConfirmed: () =>
    new ApiError(403, "EMAIL_NOT_CONFIRMED", "Confirm your email address before signing in."),
  forbidden: (message = "You do not have permission to perform this action.") =>
    new ApiError(403, "FORBIDDEN", message),
  accountDisabled: () =>
    new ApiError(403, "ACCOUNT_DISABLED", "This account is disabled or has no access."),
  notFound: (message = "The requested resource was not found.") =>
    new ApiError(404, "NOT_FOUND", message),
  methodNotAllowed: () => new ApiError(405, "METHOD_NOT_ALLOWED", "Method not allowed."),
  conflict: (message = "The request conflicts with the current state.", details?: unknown) =>
    new ApiError(409, "CONFLICT", message, details),
  payloadTooLarge: () => new ApiError(413, "PAYLOAD_TOO_LARGE", "The request body is too large."),
  unsupportedMediaType: () =>
    new ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json."),
  validation: (details?: unknown, message = "The request contains invalid data.") =>
    new ApiError(422, "VALIDATION_ERROR", message, details),
  rateLimited: (retryAfterSeconds?: number) =>
    new ApiError(
      429,
      "RATE_LIMITED",
      "Too many requests. Try again later.",
      undefined,
      retryAfterSeconds === undefined ? undefined : { "Retry-After": String(retryAfterSeconds) },
    ),
  internal: () => new ApiError(500, "INTERNAL_ERROR", "Something went wrong on our side."),
  unavailable: (message = "A required service is temporarily unavailable.") =>
    new ApiError(503, "DEPENDENCY_UNAVAILABLE", message),
} as const;
