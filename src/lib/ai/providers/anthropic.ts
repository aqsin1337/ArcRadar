import "server-only";
import { postJson } from "../http";
import {
  AiProviderError,
  type AiCompleteRequest,
  type AiCompleteResult,
  type AiProvider,
  type AiProviderInfo,
} from "../types";
import { extractJson } from "./common";

const BASE_URL = "https://api.anthropic.com";
const PATH = "/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MODEL = "claude-haiku-4-5-20251001";

/** Anthropic's Messages API (https://docs.anthropic.com/en/api/messages). Its shape differs from the
 * OpenAI-compatible providers: the key travels as `x-api-key`, the system prompt is a top-level
 * field, and there is no `response_format` — the prompt itself has to ask firmly for JSON only, which
 * `extractJson`'s braces fallback also guards against. Not verified against a real key. */
export class AnthropicProvider implements AiProvider {
  readonly info: AiProviderInfo = { id: "anthropic", name: "Anthropic Claude" };

  constructor(private readonly options: { apiKey: string; fetchImpl?: typeof fetch }) {}

  async complete(request: AiCompleteRequest): Promise<AiCompleteResult> {
    const body = await postJson({
      baseUrl: BASE_URL,
      path: PATH,
      headers: {
        "x-api-key": this.options.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: {
        model: request.model ?? DEFAULT_MODEL,
        max_tokens: request.maxOutputTokens,
        system: request.system,
        messages: [{ role: "user", content: request.user }],
      },
      signal: request.signal,
      fetchImpl: this.options.fetchImpl,
    });

    const parsed = body as {
      content?: { type?: string; text?: string }[];
      model?: string;
      usage?: { input_tokens?: number; output_tokens?: number };
    } | null;
    const text = parsed?.content?.find((block) => block.type === "text")?.text;
    if (typeof text !== "string" || text.trim() === "") {
      throw new AiProviderError("bad_response", "The provider's answer had no content.");
    }
    return {
      data: extractJson(text),
      model: parsed?.model ?? DEFAULT_MODEL,
      usage: parsed?.usage
        ? { input: parsed.usage.input_tokens ?? 0, output: parsed.usage.output_tokens ?? 0 }
        : undefined,
    };
  }
}
