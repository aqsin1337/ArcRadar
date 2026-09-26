import type { z } from "zod";
import { apiErrors } from "./errors";

export const MAX_JSON_BODY_BYTES = 64 * 1024;

export type ValidationIssue = { path: string; message: string };

/** Turns a Zod error into a stable, client-safe list. Messages never echo the submitted values. */
export function formatIssues(error: z.ZodError): { issues: ValidationIssue[] } {
  return {
    issues: error.issues.map((issue) => ({
      path: issue.path.map(String).join("."),
      message: issue.message,
    })),
  };
}

/** Validates already-parsed input; throws a 422 ApiError listing the failed fields. */
export function parseWith<S extends z.ZodType>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(input);
  if (!result.success) throw apiErrors.validation(formatIssues(result.error));
  return result.data;
}

async function readBodyText(request: Request, maxBytes: number): Promise<string> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw apiErrors.payloadTooLarge();
  if (!request.body) return "";

  // Count while reading: Content-Length can be absent (chunked) or wrong.
  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let received = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel();
        throw apiErrors.payloadTooLarge();
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch (error) {
    if (error instanceof TypeError) throw apiErrors.badRequest("The body is not valid UTF-8.");
    throw error;
  }
  return text;
}

/** Reads and validates a JSON request body. Enforces content type, size limit and the schema. */
export async function parseJsonBody<S extends z.ZodType>(
  request: Request,
  schema: S,
  maxBytes: number = MAX_JSON_BODY_BYTES,
): Promise<z.output<S>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json\s*(;|$)/i.test(contentType)) throw apiErrors.unsupportedMediaType();

  const text = await readBodyText(request, maxBytes);
  if (text.trim() === "") throw apiErrors.badRequest("A JSON request body is required.");

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw apiErrors.badRequest("The request body is not valid JSON.");
  }
  return parseWith(schema, json);
}

/** Validates the query string. Repeated keys become arrays; unknown keys are ignored. */
export function parseQuery<S extends z.ZodType>(request: Request, schema: S): z.output<S> {
  const input: Record<string, string | string[]> = {};
  for (const [key, value] of new URL(request.url).searchParams) {
    const existing = input[key];
    if (existing === undefined) input[key] = value;
    else input[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
  }
  return parseWith(schema, input);
}
