import "server-only";
import { postJson } from "../http";
import { AiProviderError, type AiCompleteRequest, type AiCompleteResult } from "../types";

/**
 * A model is asked for JSON but not every provider guarantees it comes back as nothing else (some
 * wrap it in prose or a fenced code block despite the system prompt insisting otherwise). This tries
 * the whole answer first, then falls back to the first balanced-looking `{...}` span, before giving
 * up — the caller's zod schema is still the real gate on whether the content can be trusted.
 */
export function extractJson(text: string): unknown {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // fall through to the braces heuristic below
  }
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    throw new AiProviderError("bad_response", "The provider's answer was not valid JSON.");
  }
  try {
    return JSON.parse(trimmed.slice(start, end + 1));
  } catch {
    throw new AiProviderError("bad_response", "The provider's answer was not valid JSON.");
  }
}

export type OpenAiCompatibleOptions = {
  baseUrl: string;
  path: string;
  apiKey: string;
  defaultModel: string;
  fetchImpl?: typeof fetch;
};

/**
 * Groq, OpenAI and DeepSeek all speak the same chat-completions shape (Groq and DeepSeek are
 * explicitly OpenAI-compatible). One request builder and response reader for all three; each still
 * gets its own adapter file and fixed base URL.
 */
export async function completeOpenAiCompatible(
  options: OpenAiCompatibleOptions,
  request: AiCompleteRequest,
): Promise<AiCompleteResult> {
  const body = await postJson({
    baseUrl: options.baseUrl,
    path: options.path,
    headers: { authorization: `Bearer ${options.apiKey}` },
    body: {
      model: request.model ?? options.defaultModel,
      messages: [
        { role: "system", content: request.system },
        { role: "user", content: request.user },
      ],
      max_tokens: request.maxOutputTokens,
      temperature: 0.2,
      response_format: { type: "json_object" },
    },
    signal: request.signal,
    fetchImpl: options.fetchImpl,
  });

  const parsed = asChatCompletion(body);
  return {
    data: extractJson(parsed.content),
    model: parsed.model ?? options.defaultModel,
    usage: parsed.usage,
  };
}

function asChatCompletion(body: unknown): {
  content: string;
  model: string | null;
  usage?: { input: number; output: number };
} {
  const choice = (body as { choices?: unknown[] } | null)?.choices?.[0] as
    { message?: { content?: unknown } } | undefined;
  const content = choice?.message?.content;
  if (typeof content !== "string" || content.trim() === "") {
    throw new AiProviderError("bad_response", "The provider's answer had no content.");
  }
  const usageRaw = (body as { usage?: { prompt_tokens?: number; completion_tokens?: number } })
    .usage;
  const model = (body as { model?: unknown }).model;
  return {
    content,
    model: typeof model === "string" ? model : null,
    usage: usageRaw
      ? { input: usageRaw.prompt_tokens ?? 0, output: usageRaw.completion_tokens ?? 0 }
      : undefined,
  };
}
