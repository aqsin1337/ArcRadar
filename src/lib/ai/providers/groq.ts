import "server-only";
import type { AiCompleteRequest, AiCompleteResult, AiProvider, AiProviderInfo } from "../types";
import { completeOpenAiCompatible } from "./common";

const BASE_URL = "https://api.groq.com";
const PATH = "/openai/v1/chat/completions";
const DEFAULT_MODEL = "llama-3.3-70b-versatile";

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
