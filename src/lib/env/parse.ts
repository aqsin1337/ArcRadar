import type { z } from "zod";

/** Thrown when environment variables are missing or malformed. Lists names only, never values. */
export class EnvError extends Error {
  constructor(
    readonly variables: string[],
    scope: string,
  ) {
    super(`Invalid or missing ${scope} environment variables: ${variables.join(", ")}`);
    this.name = "EnvError";
  }
}

export function parseEnv<S extends z.ZodType>(
  schema: S,
  source: unknown,
  scope: string,
): z.output<S> {
  const result = schema.safeParse(source);
  if (result.success) return result.data;

  const variables = [
    ...new Set(result.error.issues.map((issue) => String(issue.path[0] ?? "(unknown)"))),
  ];
  throw new EnvError(variables, scope);
}
