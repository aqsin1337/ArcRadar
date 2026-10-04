import "server-only";
import { ProviderError } from "./types";

/**
 * The one way a provider talks to its service. Every request goes to the provider's own fixed HTTPS
 * address (the caller only supplies a path made of encoded segments), never follows a redirect, has
 * a deadline and a size cap, and reports failures as `ProviderError`s that carry no key, URL or
 * response body. Keys travel in headers, never in the address, so they cannot end up in a log line.
 */

export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export type ProviderRequest = {
  /** The provider's API address, for example `https://www.virustotal.com/api/v3`. Must be https. */
  baseUrl: string;
  /** Starts with `/`. Build dynamic parts with `pathSegment`. */
  path: string;
  query?: Record<string, string>;
  headers: Record<string, string>;
  signal: AbortSignal;
  fetchImpl?: typeof fetch;
  maxBytes?: number;
  /**
   * A 404 normally means "the provider has no record". Some providers also use it for a rejected key:
   * this hook sees the answer's headers and may return the failure to raise instead.
   */
  onNotFound?: (headers: Headers) => ProviderError | null;
};

/** Encodes one path segment. Colons stay readable so IPv6 addresses look like they do in the docs. */
export function pathSegment(value: string): string {
  return encodeURIComponent(value).replaceAll("%3A", ":");
}

/** Seconds from a `Retry-After` header (a number of seconds or an HTTP date), or null. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | null {
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
    throw new ProviderError("bad_response", "The provider's answer was too large.");
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
      throw new ProviderError("bad_response", "The provider's answer was too large.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/**
 * GET a document as text. Resolves `null` for 404 ("the provider has no record"), throws otherwise on
 * any failure. Used directly for plain-text and other non-JSON downloads (threat feeds).
 */
export async function getText(request: ProviderRequest): Promise<string | null> {
  const base = new URL(request.baseUrl);
  const url = new URL(request.baseUrl + request.path);
  if (
    base.protocol !== "https:" ||
    url.origin !== base.origin ||
    !url.pathname.startsWith(base.pathname)
  ) {
    // A programming error, not something a user can cause: values are validated and encoded.
    throw new ProviderError("bad_response", "The provider request was refused.");
  }
  for (const [key, value] of Object.entries(request.query ?? {})) url.searchParams.set(key, value);

  const send = request.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await send(url, {
      method: "GET",
      headers: { accept: "application/json", ...request.headers },
      signal: request.signal,
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    if (request.signal.aborted) {
      throw new ProviderError("timeout", "The provider did not answer in time.");
    }
    throw new ProviderError("unavailable", "The provider could not be reached.");
  }

  if (response.status === 404) {
    const failure = request.onNotFound?.(response.headers) ?? null;
    await response.body?.cancel();
    if (failure) throw failure;
    return null;
  }
  if (!response.ok) {
    const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
    await response.body?.cancel();
    if (response.status === 401 || response.status === 403) {
      throw new ProviderError("auth", "The provider rejected the API key.");
    }
    if (response.status === 429) {
      throw new ProviderError("rate_limited", "The provider's rate limit was reached.", retryAfter);
    }
    if (response.status >= 500) {
      throw new ProviderError("unavailable", "The provider is unavailable.");
    }
    throw new ProviderError("bad_response", "The provider refused the request.");
  }

  let text: string;
  try {
    text = await readCapped(response, request.maxBytes ?? MAX_RESPONSE_BYTES);
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    if (request.signal.aborted) {
      throw new ProviderError("timeout", "The provider did not answer in time.");
    }
    throw new ProviderError("unavailable", "The provider's answer could not be read.");
  }

  return text;
}

/** GET a JSON document. Same rules as `getText`; a body that is not JSON is a `bad_response`. */
export async function getJson(request: ProviderRequest): Promise<unknown | null> {
  const text = await getText(request);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new ProviderError("bad_response", "The provider's answer was not valid JSON.");
  }
}
