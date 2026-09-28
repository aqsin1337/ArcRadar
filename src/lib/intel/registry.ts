import "server-only";
import type { ServerEnv } from "@/lib/env/server";
import { AbuseIpdbProvider } from "./providers/abuseipdb";
import { DemoProvider } from "./providers/demo";
import { VirusTotalProvider } from "./providers/virustotal";
import type { IntelKind, IntelProvider } from "./types";

/**
 * Which providers exist for this deployment. A live provider is enabled only when its key is set in
 * the server environment; with no keys at all the app still works on the demo provider alone. Keys
 * are read here, on the server, and handed to the adapters: nothing else ever sees them.
 */
export type IntelRegistry = {
  /** Live providers, most useful first. Empty when no key is configured. */
  external: IntelProvider[];
  demo: IntelProvider;
};

export function buildRegistry(
  env: Pick<ServerEnv, "VIRUSTOTAL_API_KEY" | "ABUSEIPDB_API_KEY">,
  fetchImpl?: typeof fetch,
): IntelRegistry {
  const external: IntelProvider[] = [];
  if (env.VIRUSTOTAL_API_KEY) {
    external.push(new VirusTotalProvider({ apiKey: env.VIRUSTOTAL_API_KEY, fetchImpl }));
  }
  if (env.ABUSEIPDB_API_KEY) {
    external.push(new AbuseIpdbProvider({ apiKey: env.ABUSEIPDB_API_KEY, fetchImpl }));
  }
  return { external, demo: new DemoProvider() };
}

const LOOKUP_METHOD = {
  ip: "lookupIp",
  domain: "lookupDomain",
  url: "lookupUrl",
  hash: "lookupHash",
} as const satisfies Record<IntelKind, keyof IntelProvider>;

/** Whether the provider can answer this kind of lookup at all. */
export function supportsKind(provider: IntelProvider, kind: IntelKind): boolean {
  return typeof provider[LOOKUP_METHOD[kind]] === "function";
}
