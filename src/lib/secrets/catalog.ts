import { z } from "zod";

/**
 * The settings an administrator can save from the app. Safe to import from a Client Component
 * (no secrets here, only names, labels and the rules a value must follow).
 *
 * `secret` values are never shown again after saving (only the last characters); `text` values
 * (a repository name, a branch) are not secret and are shown as saved; a `flag` is an on/off switch.
 * OLLAMA_BASE_URL is deliberately not here: it stays a server variable, never admin input
 * (docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md, "Ollama and SSRF").
 */
export const SECRET_GROUPS = [
  "Threat intelligence",
  "AI providers",
  "Wazuh rules repository",
] as const;
export type SecretGroup = (typeof SECRET_GROUPS)[number];

export type SecretKind = "secret" | "text" | "flag";

export type SecretDefinition = {
  name: SecretName;
  label: string;
  group: SecretGroup;
  kind: SecretKind;
  help: string;
};

export const SECRET_NAMES = [
  "VIRUSTOTAL_API_KEY",
  "ABUSEIPDB_API_KEY",
  "OTX_API_KEY",
  "NVD_API_KEY",
  "SHODAN_INTERNETDB",
  "GROQ_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "DEEPSEEK_API_KEY",
  "GITHUB_TOKEN",
  "GITHUB_RULES_REPO",
  "GITHUB_RULES_BRANCH",
] as const;
export type SecretName = (typeof SECRET_NAMES)[number];

export const SECRET_CATALOG: readonly SecretDefinition[] = [
  {
    name: "VIRUSTOTAL_API_KEY",
    label: "VirusTotal",
    group: "Threat intelligence",
    kind: "secret",
    help: "IP, domain, URL and file-hash verdicts.",
  },
  {
    name: "ABUSEIPDB_API_KEY",
    label: "AbuseIPDB",
    group: "Threat intelligence",
    kind: "secret",
    help: "IP address abuse reports.",
  },
  {
    name: "OTX_API_KEY",
    label: "AlienVault OTX",
    group: "Threat intelligence",
    kind: "secret",
    help: "Community pulses for IPs, domains, URLs and hashes.",
  },
  {
    name: "NVD_API_KEY",
    label: "NVD (CVE import)",
    group: "Threat intelligence",
    kind: "secret",
    help: "Lets an administrator import a CVE from the National Vulnerability Database.",
  },
  {
    name: "SHODAN_INTERNETDB",
    label: "Shodan InternetDB",
    group: "Threat intelligence",
    kind: "flag",
    help: "Free, needs no key. Switch it on to add open ports and known vulnerabilities for an IP.",
  },
  {
    name: "GROQ_API_KEY",
    label: "Groq",
    group: "AI providers",
    kind: "secret",
    help: "Fast hosted models. Choose it as the active provider on the Integrations page.",
  },
  {
    name: "OPENAI_API_KEY",
    label: "OpenAI",
    group: "AI providers",
    kind: "secret",
    help: "GPT models.",
  },
  {
    name: "ANTHROPIC_API_KEY",
    label: "Anthropic (Claude)",
    group: "AI providers",
    kind: "secret",
    help: "Claude models.",
  },
  {
    name: "DEEPSEEK_API_KEY",
    label: "DeepSeek",
    group: "AI providers",
    kind: "secret",
    help: "DeepSeek models.",
  },
  {
    name: "GITHUB_TOKEN",
    label: "GitHub token",
    group: "Wazuh rules repository",
    kind: "secret",
    help: "A fine-grained token with Contents: Read and write on the rules repository only.",
  },
  {
    name: "GITHUB_RULES_REPO",
    label: "Rules repository",
    group: "Wazuh rules repository",
    kind: "text",
    help: "owner/name, for example aqsin1337/wazuh_rules.",
  },
  {
    name: "GITHUB_RULES_BRANCH",
    label: "Branch",
    group: "Wazuh rules repository",
    kind: "text",
    help: "Optional. Defaults to main.",
  },
];

export const secretDefinition = (name: string): SecretDefinition | undefined =>
  SECRET_CATALOG.find((entry) => entry.name === name);

const secretValue = z
  .string()
  .trim()
  .min(8, "That is too short to be a key.")
  .max(500, "That is too long to be a key.")
  .regex(/^[\x21-\x7e]+$/, "A key has no spaces or special characters.");

const repoValue = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/, "Use the form owner/name.");

const branchValue = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9_./-]{1,100}$/, "Letters, digits and . _ / - only.");

/** The schema a value must pass for this setting; a flag is always exactly "true". */
export function valueSchemaFor(kind: SecretKind, name: SecretName): z.ZodType<string> {
  if (kind === "flag") return z.literal("true");
  if (name === "GITHUB_RULES_REPO") return repoValue;
  if (name === "GITHUB_RULES_BRANCH") return branchValue;
  return secretValue;
}
