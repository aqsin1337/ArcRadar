import type { ServerEnv } from "@/lib/env/server";

/** The provider catalog seeded in migration 20260925100400, plus wazuh (20260927110000) and the
 * five AI providers (20260927130000). */
export const INTEGRATION_PROVIDERS = [
  "demo",
  "virustotal",
  "abuseipdb",
  "otx",
  "nvd",
  "shodan",
  "misp",
  "opencti",
  "wazuh",
  "abusech",
  "cisa_kev",
  "groq",
  "openai",
  "anthropic",
  "deepseek",
  "ollama",
] as const;

export type IntegrationProvider = (typeof INTEGRATION_PROVIDERS)[number];

/** The AI-capable providers, in the order they should be offered as the active one. Groq is first:
 * it is the one the project ships configured by default. */
export const AI_PROVIDERS = ["groq", "openai", "anthropic", "deepseek", "ollama"] as const;

/** Which server-side environment variable, if any, a provider needs. `demo` and `wazuh` need none:
 * demo always works, wazuh is configured per API key rather than one shared server secret. Ollama
 * is "configured" once its local base URL is set, not an API key. */
export const PROVIDER_ENV_KEYS: Partial<Record<IntegrationProvider, keyof ServerEnv>> = {
  virustotal: "VIRUSTOTAL_API_KEY",
  abuseipdb: "ABUSEIPDB_API_KEY",
  otx: "OTX_API_KEY",
  nvd: "NVD_API_KEY",
  shodan: "SHODAN_INTERNETDB",
  groq: "GROQ_API_KEY",
  openai: "OPENAI_API_KEY",
  anthropic: "ANTHROPIC_API_KEY",
  deepseek: "DEEPSEEK_API_KEY",
  ollama: "OLLAMA_BASE_URL",
};
