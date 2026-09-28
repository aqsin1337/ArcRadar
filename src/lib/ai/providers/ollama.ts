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

const PATH = "/api/chat";
const DEFAULT_MODEL = "llama3.1";

/** A local Ollama server (https://github.com/ollama/ollama/blob/main/docs/api.md), reached at
 * `OLLAMA_BASE_URL` — a trusted, server-only environment variable, never admin-UI input (see
 * docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "Ollama and SSRF"), which is also why this is the only
 * adapter allowed to use plain http. Not verified against a real server: no local model server exists
 * in the lab yet. */
export class OllamaProvider implements AiProvider {
  readonly info: AiProviderInfo = { id: "ollama", name: "Ollama (local)" };

  constructor(private readonly options: { baseUrl: string; fetchImpl?: typeof fetch }) {}

  async complete(request: AiCompleteRequest): Promise<AiCompleteResult> {
    const body = await postJson({
      baseUrl: this.options.baseUrl,
      path: PATH,
      headers: {},
      body: {
        model: request.model ?? DEFAULT_MODEL,
        messages: [
          { role: "system", content: request.system },
          { role: "user", content: request.user },
        ],
        format: "json",
        stream: false,
        options: { num_predict: request.maxOutputTokens },
      },
      signal: request.signal,
      fetchImpl: this.options.fetchImpl,
      allowInsecure: true,
    });

    const parsed = body as {
      message?: { content?: string };
      model?: string;
      prompt_eval_count?: number;
      eval_count?: number;
    } | null;
    const content = parsed?.message?.content;
    if (typeof content !== "string" || content.trim() === "") {
      throw new AiProviderError("bad_response", "The provider's answer had no content.");
    }
    return {
      data: extractJson(content),
      model: parsed?.model ?? DEFAULT_MODEL,
      usage:
        parsed?.prompt_eval_count !== undefined || parsed?.eval_count !== undefined
          ? { input: parsed?.prompt_eval_count ?? 0, output: parsed?.eval_count ?? 0 }
          : undefined,
    };
  }
}
