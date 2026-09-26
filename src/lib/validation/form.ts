import type { z } from "zod";

/** First message per top-level field, for showing inline errors. `formErrors` collects the rest. */
export function fieldErrorsFromZod(error: z.ZodError): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const issue of error.issues) {
    const key = issue.path.length > 0 ? String(issue.path[0]) : "";
    if (!(key in errors)) errors[key] = issue.message;
  }
  return errors;
}

/** Reads a text input from FormData as a string (a missing field becomes ""). */
export function formText(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}
