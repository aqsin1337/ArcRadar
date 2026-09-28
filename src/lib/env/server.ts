import "server-only";
import { z } from "zod";
import { parseEnv } from "./parse";

// Empty values (`FOO=`) count as "not configured".
const optionalSecret = z
  .string()
  .trim()
  .transform((value) => (value === "" ? undefined : value))
  .optional();

// Server-only secrets. Never prefix these with NEXT_PUBLIC_ and never import this module from a
// Client Component (the `server-only` import above turns that mistake into a build error).
const serverEnvSchema = z.object({
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  VIRUSTOTAL_API_KEY: optionalSecret,
  ABUSEIPDB_API_KEY: optionalSecret,
  OTX_API_KEY: optionalSecret,
  SHODAN_API_KEY: optionalSecret,
  NVD_API_KEY: optionalSecret,
  GROQ_API_KEY: optionalSecret,
  OPENAI_API_KEY: optionalSecret,
  ANTHROPIC_API_KEY: optionalSecret,
  DEEPSEEK_API_KEY: optionalSecret,
  // A local server address, not a secret, but still never sent to the client and never editable
  // from the admin UI (see docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "Ollama and SSRF").
  OLLAMA_BASE_URL: optionalSecret,
});

export type ServerEnv = z.output<typeof serverEnvSchema>;

export function parseServerEnv(source: unknown): ServerEnv {
  return parseEnv(serverEnvSchema, source, "server");
}

export function getServerEnv(): ServerEnv {
  return parseServerEnv(process.env);
}
