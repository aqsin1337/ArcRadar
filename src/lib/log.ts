/**
 * Minimal structured server logging (Vercel captures stdout/stderr). Log identifiers and error
 * codes, never request bodies, credentials, tokens or provider keys.
 */
export function logError(event: string, error: unknown, context: Record<string, unknown> = {}) {
  const details =
    error instanceof Error
      ? {
          error_name: error.name,
          error_message: error.message,
          error_code: (error as { code?: unknown }).code,
          stack: error.stack?.split("\n").slice(0, 8).join("\n"),
        }
      : { error_message: String(error) };

  console.error(JSON.stringify({ level: "error", event, ...context, ...details }));
}

export function logWarn(event: string, context: Record<string, unknown> = {}) {
  console.warn(JSON.stringify({ level: "warn", event, ...context }));
}
