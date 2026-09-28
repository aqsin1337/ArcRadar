// Creates an ArcRadar API key by signing in as an administrator and calling POST /api/api-keys.
// The key is printed once; ArcRadar keeps only its hash, so it cannot be shown again.
//
//   ARCRADAR_EMAIL=admin@arcradar.test ARCRADAR_PASSWORD='...' npm run apikey:create -- \
//       --url http://localhost:3000 --name "Wazuh lab" --days 90
//
//   --url    where ArcRadar runs (default http://localhost:3000, or ARCRADAR_URL)
//   --name   what the key is for (default "Wazuh Manager")
//   --days   how long it lasts, 1-365 (default 365), or "never"
//
// The password is read from the environment, never from the command line (which shells remember).
// Only an administrator can make a key with the ingest:wazuh scope.
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

function fail(message) {
  console.error(message);
  process.exitCode = 1; // not process.exit(): on Windows that can trip a libuv assertion with fetch timers pending
}

async function call(base, path, body, cookie) {
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { response, json, text };
}

async function main() {
  const base = (option("url") ?? process.env.ARCRADAR_URL ?? "http://localhost:3000").replace(
    /\/+$/,
    "",
  );
  const name = option("name") ?? "Wazuh Manager";
  const days = option("days");
  const email = process.env.ARCRADAR_EMAIL;
  const password = process.env.ARCRADAR_PASSWORD;
  if (!email || !password) {
    return fail("Set ARCRADAR_EMAIL and ARCRADAR_PASSWORD (an administrator's sign-in) first.");
  }

  let expires;
  if (days === undefined) expires = undefined;
  else if (days === "never") expires = null;
  else if (/^\d+$/.test(days)) expires = Number(days);
  else return fail('--days must be a number from 1 to 365, or "never".');

  const login = await call(base, "/api/auth/login", { email, password });
  if (!login.response.ok) {
    return fail(
      `Sign-in failed (${login.response.status}): ${login.json?.error?.message ?? login.text.slice(0, 200)}`,
    );
  }
  const cookie = login.response.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .filter((pair) => !pair.endsWith("="))
    .join("; ");

  const created = await call(
    base,
    "/api/api-keys",
    {
      name,
      scopes: ["ingest:wazuh"],
      ...(expires === undefined ? {} : { expires_in_days: expires }),
    },
    cookie,
  );
  if (created.response.status !== 201) {
    return fail(
      `Could not create the key (${created.response.status}): ${created.json?.error?.message ?? created.text.slice(0, 200)}`,
    );
  }

  const { key, api_key: info } = created.json.data;
  console.log(
    `API key "${info.name}" created (${info.scopes.join(", ")}), expires ${info.expires_at ?? "never"}.`,
  );
  console.log("");
  console.log(`  ${key}`);
  console.log("");
  console.log("Copy it now: ArcRadar stores only a hash and cannot show it again.");
  console.log(
    "Put it in the <api_key> tag of the Wazuh integration block (deploy/wazuh/ossec-integration.xml).",
  );
}

await main();
