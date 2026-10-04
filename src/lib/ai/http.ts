import "server-only";
import { AiProviderError } from "./types";

/**
 * The one way an AI provider is called. Every request goes to the provider's own fixed HTTPS
 * address (never built from admin input — see docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "Ollama and
 * SSRF"), never follows a redirect, has a deadline and a size cap, and reports failures as
 * `AiProviderError`s that carry no key, prompt or response body. This mirrors every rule of
 * `src/lib/intel/http.ts`'s `getJson` for the POST case AI calls need.
 */

export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export type AiHttpRequest = {
  /** The provider's fixed API address, for example `https://api.groq.com`. Must be https, unless
   * `allowInsecure` is set. */
  baseUrl: string;
  /** Starts with `/`. Never built from a value a caller supplied. */
  path: string;
  headers: Record<string, string>;
  body: unknown;
  signal: AbortSignal;
  fetchImpl?: typeof fetch;
  maxBytes?: number;
  /**
   * Allows plain http, for exactly one case: a local Ollama server whose address is a trusted,
   * server-only environment variable (never user or admin-session input — see
   * docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "Ollama and SSRF"). Every other provider keeps the
   * https-only rule `getJson` also enforces.
   */
  allowInsecure?: boolean;
};

/** Seconds from a `Retry-After` header (a number of seconds or an HTTP date), or null. */
function parseRetryAfter(value: string | null, now = Date.now()): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.min(Math.max(Math.ceil(seconds), 0), 3600);
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.min(Math.max(Math.ceil((date - now) / 1000), 0), 3600);
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel();
    throw new AiProviderError("bad_response", "The provider's answer was too large.");
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let received = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel();
      throw new AiProviderError("bad_response", "The provider's answer was too large.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/** POSTs a JSON body and parses a JSON answer. Throws `AiProviderError` for any failure — there is
 * no "not found" case here, unlike a lookup: a bad status is always a real failure. */
export async function postJson(request: AiHttpRequest): Promise<unknown> {
  const base = new URL(request.baseUrl);
  const url = new URL(request.baseUrl + request.path);
  const schemeOk = request.allowInsecure
    ? base.protocol === "https:" || base.protocol === "http:"
    : base.protocol === "https:";
  if (!schemeOk || url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) {
    // A programming error, not something a user can cause: the base and path are both fixed code.
    throw new AiProviderError("bad_response", "The provider request was refused.");
  }

  const send = request.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await send(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        ...request.headers,
      },
      body: JSON.stringify(request.body),
      signal: request.signal,
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    if (request.signal.aborted) {
      throw new AiProviderError("timeout", "The provider did not answer in time.");
    }
    throw new AiProviderError("unavailable", "The provider could not be reached.");
  }

  if (!response.ok) {
    const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
    await response.body?.cancel();
    if (response.status === 401 || response.status === 403) {
      throw new AiProviderError("auth", "The provider rejected the API key.");
    }
    if (response.status === 429) {
      throw new AiProviderError(
        "rate_limited",
        "The provider's rate limit was reached.",
        retryAfter,
      );
    }
    if (response.status >= 500) {
      throw new AiProviderError("unavailable", "The provider is unavailable.");
    }
    throw new AiProviderError("bad_response", "The provider refused the request.");
  }

  let text: string;
  try {
    text = await readCapped(response, request.maxBytes ?? MAX_RESPONSE_BYTES);
  } catch (error) {
    if (error instanceof AiProviderError) throw error;
    if (request.signal.aborted) {
      throw new AiProviderError("timeout", "The provider did not answer in time.");
    }
    throw new AiProviderError("unavailable", "The provider's answer could not be read.");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new AiProviderError("bad_response", "The provider's answer was not valid JSON.");
  }
}
