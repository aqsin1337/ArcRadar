// Copies the local Supabase stack's URL and keys into .env.local without printing them.
// Existing lines (for example provider API keys) are preserved.
// Usage: npm run db:env   (the local stack must be running: npm run db:start)
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const status = spawnSync("npx supabase status -o env", {
  cwd: root,
  encoding: "utf8",
  shell: true,
});
if (status.status !== 0) {
  console.error(
    "Could not read `supabase status`. Is the local stack running? Try: npm run db:start",
  );
  process.exit(1);
}

const local = {};
for (const line of status.stdout.split(/\r?\n/)) {
  const match = /^([A-Z_]+)="?(.*?)"?$/.exec(line);
  if (match) local[match[1]] = match[2];
}

const updates = {
  NEXT_PUBLIC_SUPABASE_URL: local.API_URL,
  NEXT_PUBLIC_SUPABASE_ANON_KEY: local.ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY: local.SERVICE_ROLE_KEY,
};
const missing = Object.entries(updates).filter(([, value]) => !value);
if (missing.length > 0) {
  console.error(`Missing from supabase status: ${missing.map(([key]) => key).join(", ")}`);
  process.exit(1);
}

// Turns on the demo-account buttons on the sign-in page (the seed creates those users). Only added
// when absent, so you can switch it off by hand in .env.local.
const defaults = { NEXT_PUBLIC_DEMO_LOGINS: "true" };

const target = join(root, ".env.local");
const lines = existsSync(target) ? readFileSync(target, "utf8").split(/\r?\n/) : [];
for (const [key, value] of Object.entries(updates)) {
  const index = lines.findIndex((line) => line.startsWith(`${key}=`));
  if (index >= 0) lines[index] = `${key}=${value}`;
  else lines.push(`${key}=${value}`);
}
for (const [key, value] of Object.entries(defaults)) {
  if (!lines.some((line) => line.startsWith(`${key}=`))) lines.push(`${key}=${value}`);
}
writeFileSync(
  target,
  lines.filter((line, i) => line !== "" || i < lines.length - 1).join("\n") + "\n",
);
console.log(`Updated ${Object.keys(updates).join(", ")} in .env.local`);
