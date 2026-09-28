import { readFileSync } from "node:fs";
import { join } from "node:path";

export const DEMO_PASSWORD = "ArcRadar-Demo-1!";
export const AUTH_DIR = join(process.cwd(), "tests", "e2e", ".auth");
export const STORAGE = {
  viewer: join(AUTH_DIR, "viewer.json"),
  analyst: join(AUTH_DIR, "analyst.json"),
  admin: join(AUTH_DIR, "admin.json"),
};

/** Reads local Supabase settings from .env.local (used only for test set-up and clean-up). */
export function localEnv() {
  const env: Record<string, string> = {};
  for (const line of readFileSync(join(process.cwd(), ".env.local"), "utf8").split(/\r?\n/)) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
  }
  return env;
}

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:3000";

/** Wazuh alerts of the kind a Manager sends, marked so that a test can find and remove only its own. */
export function wazuhAlerts(marker: string) {
  const now = Date.now();
  const stamped = (offsetSeconds: number) =>
    new Date(now - offsetSeconds * 1000).toISOString().replace("Z", "+0000");
  const agent = { id: marker, name: `${marker}-WIN10`, ip: "192.168.56.170" };
  return [
    {
      id: `${marker}.1`,
      timestamp: stamped(30),
      rule: {
        id: "60204",
        level: 10,
        description: `${marker} multiple logon failures`,
        groups: ["windows", "authentication_failures"],
        mitre: { id: ["T1110", "T1059.001"] },
      },
      agent,
      manager: { name: "e2e-manager" },
      full_log: `${marker} raw log line`,
      decoder: { name: "windows_eventchannel" },
      data: { win: { eventdata: { ipAddress: "198.51.100.180" } } },
      location: "EventChannel",
    },
    {
      id: `${marker}.2`,
      timestamp: stamped(20),
      rule: {
        id: "100201",
        level: 12,
        description: `${marker} outbound connection`,
        groups: ["sysmon", "sysmon_event3"],
      },
      agent,
      manager: { name: "e2e-manager" },
      full_log: `${marker} sysmon log line`,
      data: {
        win: {
          system: { providerName: "Microsoft-Windows-Sysmon", eventID: "3" },
          eventdata: { destinationIp: "203.0.113.180", destinationPort: "4444" },
        },
      },
      location: "EventChannel",
    },
    {
      id: `${marker}.3`,
      timestamp: stamped(10),
      rule: {
        id: "60106",
        level: 3,
        description: `${marker} routine logon`,
        groups: ["authentication_success"],
      },
      agent,
      manager: { name: "e2e-manager" },
      full_log: `${marker} routine`,
      location: "EventChannel",
    },
  ];
}

/** Sends alerts to the ingest endpoint the way a Wazuh Manager does: no cookies, just the key. */
export async function ingest(key: string | null, alerts: unknown[]) {
  return fetch(`${BASE_URL}/api/ingest/wazuh`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(key ? { authorization: `Bearer ${key}` } : {}),
    },
    body: JSON.stringify({ alerts }),
  });
}

/** Removes what a telemetry test created (by its marker) with the service role. */
export async function cleanTelemetry(marker: string) {
  const gone = { method: "DELETE", headers: { prefer: "return=minimal" } };
  await adminFetch(`/rest/v1/alerts?source_event_id=like.e2e-manager:${marker}*`, gone);
  await adminFetch(`/rest/v1/events?source_event_id=like.e2e-manager:${marker}*`, gone);
  await adminFetch(`/rest/v1/assets?external_id=eq.${marker}`, gone);
  await adminFetch("/rest/v1/indicators?value=in.(198.51.100.180,203.0.113.180)", gone);
  await adminFetch(`/rest/v1/api_keys?name=like.${marker}*`, gone);
}

/** Service-role REST helper for creating and removing throwaway users. */
export async function adminFetch(path: string, init: RequestInit = {}) {
  const env = localEnv();
  return fetch(`${env.NEXT_PUBLIC_SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "content-type": "application/json",
      ...init.headers,
    },
  });
}
