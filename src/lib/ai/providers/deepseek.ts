import "server-only";
import type { AiCompleteRequest, AiCompleteResult, AiProvider, AiProviderInfo } from "../types";
import { completeOpenAiCompatible } from "./common";

const BASE_URL = "https://api.deepseek.com";
const PATH = "/chat/completions";
const DEFAULT_MODEL = "deepseek-chat";

/** DeepSeek's OpenAI-compatible chat completions API (https://api-docs.deepseek.com). Not verified
 * against a real key, the same caveat as OpenAI's adapter. */
export class DeepSeekProvider implements AiProvider {
  readonly info: AiProviderInfo = { id: "deepseek", name: "DeepSeek" };

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
