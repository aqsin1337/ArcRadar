import "server-only";
import type { ServerEnv } from "@/lib/env/server";
import { logWarn } from "@/lib/log";
import { AnthropicProvider } from "./providers/anthropic";
import { DeepSeekProvider } from "./providers/deepseek";
import { GroqProvider } from "./providers/groq";
import { OllamaProvider } from "./providers/ollama";
import { OpenAiProvider } from "./providers/openai";
import type { AiProvider, AiProviderId } from "./types";

/**
 * Which AI providers this deployment can use: one entry per server-side key that is actually set (or,
 * for Ollama, a well-formed base URL). Keys are read here, on the server, and handed to the adapters:
 * nothing else ever sees them. Mirrors `src/lib/intel/registry.ts`.
 */
export type AiRegistry = ReadonlyMap<AiProviderId, AiProvider>;

type RegistryEnv = Pick<
  ServerEnv,
  "GROQ_API_KEY" | "OPENAI_API_KEY" | "ANTHROPIC_API_KEY" | "DEEPSEEK_API_KEY" | "OLLAMA_BASE_URL"
>;

export function buildAiRegistry(env: RegistryEnv, fetchImpl?: typeof fetch): AiRegistry {
  const registry = new Map<AiProviderId, AiProvider>();

  if (env.GROQ_API_KEY) {
    registry.set("groq", new GroqProvider({ apiKey: env.GROQ_API_KEY, fetchImpl }));
  }
  if (env.OPENAI_API_KEY) {
    registry.set("openai", new OpenAiProvider({ apiKey: env.OPENAI_API_KEY, fetchImpl }));
  }
  if (env.ANTHROPIC_API_KEY) {
    registry.set("anthropic", new AnthropicProvider({ apiKey: env.ANTHROPIC_API_KEY, fetchImpl }));
  }
  if (env.DEEPSEEK_API_KEY) {
    registry.set("deepseek", new DeepSeekProvider({ apiKey: env.DEEPSEEK_API_KEY, fetchImpl }));
  }
  if (env.OLLAMA_BASE_URL) {
    let protocol: string | null = null;
    try {
      protocol = new URL(env.OLLAMA_BASE_URL).protocol;
    } catch {
      protocol = null;
    }
    if (protocol === "http:" || protocol === "https:") {
      registry.set("ollama", new OllamaProvider({ baseUrl: env.OLLAMA_BASE_URL, fetchImpl }));
    } else {
      // A malformed OLLAMA_BASE_URL must not take the rest of AI down with it.
      logWarn("ai.ollama_base_url_invalid", {});
    }
  }

  return registry;
}
