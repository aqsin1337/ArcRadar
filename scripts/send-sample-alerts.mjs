// Sends a handful of sample Wazuh alerts to a running ArcRadar, so the whole pipeline (API key,
// ingest endpoint, events, alerts, assets, indicators, the Telemetry page) can be tried without a
// Wazuh Manager. The samples are fictional and say so (manager "sample-manager", agents SAMPLE-*).
//
//   npm run ingest:sample -- --url http://localhost:3000 --key arc_...
//   ARCRADAR_URL=... ARCRADAR_INGEST_KEY=... npm run ingest:sample
//   npm run ingest:sample -- --replay        # send the same alerts (same ids) again: nothing new is created
//   npm run ingest:sample -- --siem splunk   # the Splunk samples, through /api/ingest/splunk (needs an ingest:splunk key)
//
// Each run gives the alerts fresh ids and the current time, so running it twice creates twice as much;
// --replay reuses the ids of the previous run (kept in a temp file) to show that a resend is harmless.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

function fail(message) {
  console.error(message);
  process.exitCode = 1; // not process.exit(): on Windows that can trip a libuv assertion with fetch timers pending
}

// Wazuh writes offsets without a colon, e.g. 2026-09-26T10:00:00.000+0000.
const wazuhTime = (date) => date.toISOString().replace("Z", "+0000");

async function main() {
  const base = (option("url") ?? process.env.ARCRADAR_URL ?? "http://localhost:3000").replace(
    /\/+$/,
    "",
  );
  const key = option("key") ?? process.env.ARCRADAR_INGEST_KEY;
  const replay = args.includes("--replay");
  const siem = option("siem") ?? "wazuh";
  if (siem !== "wazuh" && siem !== "splunk")
    return fail(`Unknown --siem ${siem} (wazuh or splunk).`);
  if (!key) {
    return fail(
      "Give the API key with --key arc_... or ARCRADAR_INGEST_KEY (make one with: npm run apikey:create).",
    );
  }

  const samples = JSON.parse(
    readFileSync(new URL(`./fixtures/${siem}-sample-alerts.json`, import.meta.url), "utf8"),
  );
  const memory = join(tmpdir(), `arcradar-sample-alert-ids-${siem}.json`);

  let ids;
  if (replay && existsSync(memory)) {
    ids = JSON.parse(readFileSync(memory, "utf8"));
  } else {
    const epoch = Math.floor(Date.now() / 1000);
    ids = samples.map((_, index) => `${epoch}.${1000001 + index}`);
    writeFileSync(memory, JSON.stringify(ids));
  }

  const now = Date.now();
  const alerts = samples.map((sample, index) => {
    const at = new Date(now - (samples.length - 1 - index) * 60_000); // the newest last, a minute apart, ending now
    if (siem === "splunk") {
      return {
        ...sample,
        sid: `${sample.sid}.${ids[index]}`,
        result: { ...sample.result, _time: String(Math.floor(at.getTime() / 1000)) },
      };
    }
    return {
      ...sample,
      id: ids[index] ?? `${Math.floor(now / 1000)}.${1000001 + index}`,
      timestamp: wazuhTime(at),
    };
  });

  const response = await fetch(`${base}/api/ingest/${siem}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
    body: JSON.stringify({ alerts }),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}

  if (!response.ok || !json?.success) {
    return fail(
      `ArcRadar answered ${response.status}: ${json?.error?.message ?? text.slice(0, 300)}`,
    );
  }
  const data = json.data;
  console.log(`Sent ${data.received} sample alerts to ${base}`);
  console.log(
    `  events created ${data.events_created}, alerts created ${data.alerts_created}, duplicates ${data.duplicates}, ` +
      `assets created ${data.assets_created}, indicators created ${data.indicators_created}, rejected ${data.rejected.length}`,
  );
  for (const item of data.rejected) console.log(`  rejected #${item.index}: ${item.reason}`);
  console.log(`Open ${base}/telemetry and ${base}/alerts?source=${siem} to see them.`);
}

await main();
