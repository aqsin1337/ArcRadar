import "server-only";
import type { AiCompleteRequest, AiCompleteResult, AiProvider, AiProviderInfo } from "../types";
import { completeOpenAiCompatible } from "./common";

const BASE_URL = "https://api.groq.com";
const PATH = "/openai/v1/chat/completions";
// Groq decommissioned llama-3.3-70b-versatile (confirmed live: a chat-completions call now answers 404
// model_not_found). gpt-oss-120b is OpenAI's own open-weight model served by Groq, supports json_object
// response_format and stays well within this app's fixed per-kind token budgets even with its hidden
// reasoning tokens counted in (checked live: ~60-110 completion tokens against a 350-token budget).
const DEFAULT_MODEL = "openai/gpt-oss-120b";

/** Groq's OpenAI-compatible chat completions API (https://console.groq.com/docs/api-reference). The
 * default, working adapter: this is the provider the project ships configured. */
export class GroqProvider implements AiProvider {
  readonly info: AiProviderInfo = { id: "groq", name: "Groq" };

  constructor(private readonly options: { apiKey: string; fetchImpl?: typeof fetch }) {}

  complete(request: AiCompleteRequest): Promise<AiCompleteResult> {
    return completeOpenAiCompatible(
      {
        baseUrl: BASE_URL,
        path: PATH,
        apiKey: this.options.apiKey,
        defaultModel: DEFAULT_MODEL,
        fetchImpl: this.options.fetchImpl,
      },
      request,
    );
  }
}
