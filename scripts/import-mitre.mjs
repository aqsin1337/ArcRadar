// Imports the MITRE ATT&CK technique catalog (names and tactics, for the ATT&CK matrix page) into
// ArcRadar, directly against the database with the service-role key, through import_mitre_attack().
//
// This is a script and not an app feature on purpose: the catalog is a ~54 MB download, far too heavy
// for a serverless request, and it changes a few times a year. Run it once after setting up a
// database, and again when you want the newest release. Techniques are reference data: rerunning it
// only refreshes their names, tactics and descriptions.
//
//   Local database (after `npm run db:env`; the key is read from .env.local for the local stack only):
//     npm run import:mitre
//   A hosted project (the service-role key is never read from a file for a remote database):
//     SUPABASE_SERVICE_ROLE_KEY=... npm run import:mitre -- --url https://<ref>.supabase.co
//   From a file you already downloaded:
//     npm run import:mitre -- --file enterprise-attack.json
//
// Safe to run more than once: nothing is created twice.
import { readFileSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import { ATTACK_STIX_URL, chunk, transformStix } from "./lib/mitre-transform.mjs";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

function fail(message) {
  console.error(message);
  process.exitCode = 1; // not process.exit(): on Windows that can trip a libuv assertion with fetch timers pending
}

function envFileValue(name) {
  try {
    const line = readFileSync(new URL("../.env.local", import.meta.url), "utf8")
      .split(/\r?\n/)
      .find((entry) => entry.startsWith(`${name}=`));
    return line?.slice(name.length + 1).trim() || undefined;
  } catch {
    return undefined;
  }
}

async function main() {
  const explicitUrl = option("url") ?? process.env.SUPABASE_URL;
  const url =
    explicitUrl ?? process.env.NEXT_PUBLIC_SUPABASE_URL ?? envFileValue("NEXT_PUBLIC_SUPABASE_URL");
  if (!url) return fail("Set NEXT_PUBLIC_SUPABASE_URL (or SUPABASE_URL), or pass --url.");

  // Only the local stack's key may come from .env.local (npm run db:env writes it for that stack).
  const isLocal = !explicitUrl && /^https?:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(url);
  const serviceKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ??
    (isLocal ? envFileValue("SUPABASE_SERVICE_ROLE_KEY") : undefined);
  if (!serviceKey) return fail("Set SUPABASE_SERVICE_ROLE_KEY first (Project Settings > API).");

  let bundle;
  const file = option("file");
  if (file) {
    console.log(`Reading ${file} ...`);
    bundle = JSON.parse(readFileSync(file, "utf8"));
  } else {
    console.log("Downloading the ATT&CK Enterprise catalog (about 54 MB) ...");
    const response = await fetch(ATTACK_STIX_URL, { redirect: "error" });
    if (!response.ok) return fail(`The download failed with status ${response.status}.`);
    bundle = await response.json();
  }

  const { techniques } = transformStix(bundle);
  console.log(`Found ${techniques.length} techniques.`);
  if (techniques.length === 0)
    return fail("The catalog looks empty or malformed; nothing was imported.");

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  let imported = 0;
  let skipped = 0;
  for (const part of chunk(techniques, 250)) {
    const { data, error } = await admin.rpc("import_mitre_attack", { p: { techniques: part } });
    if (error) return fail(`Importing techniques failed: ${error.message}`);
    imported += data.techniques ?? 0;
    skipped += data.skipped ?? 0;
  }
  console.log(
    `Imported ${imported} techniques (${skipped} skipped: entries the database refused).`,
  );
}

main().catch((error) => fail(`Import failed: ${error.message}`));
