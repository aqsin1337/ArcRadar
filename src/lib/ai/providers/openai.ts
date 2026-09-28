import "server-only";
import type { AiCompleteRequest, AiCompleteResult, AiProvider, AiProviderInfo } from "../types";
import { completeOpenAiCompatible } from "./common";

const BASE_URL = "https://api.openai.com";
const PATH = "/v1/chat/completions";
const DEFAULT_MODEL = "gpt-4o-mini";

/** OpenAI's chat completions API. Not verified against a real key (no key has been available while
 * building this), the same caveat the live intel providers carried before one existed. */
export class OpenAiProvider implements AiProvider {
  readonly info: AiProviderInfo = { id: "openai", name: "OpenAI" };

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
