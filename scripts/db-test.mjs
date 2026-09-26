// Runs supabase/tests/*.test.sql against the local Supabase database.
// Usage: npm run db:test   (the local stack must be running: npm run db:start)
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const config = readFileSync(join(root, "supabase", "config.toml"), "utf8");
const projectId = /^project_id\s*=\s*"([^"]+)"/m.exec(config)?.[1];
if (!projectId) {
  console.error("Could not read project_id from supabase/config.toml");
  process.exit(1);
}

const container = `supabase_db_${projectId}`;
const testDir = join(root, "supabase", "tests");
const files = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.sql"))
  .sort();
let failed = false;

for (const file of files) {
  console.log(`\n=== ${file} ===`);
  const result = spawnSync(
    "docker",
    [
      "exec",
      "-i",
      container,
      "psql",
      "-U",
      "postgres",
      "-d",
      "postgres",
      "-v",
      "ON_ERROR_STOP=1",
      "-q",
    ],
    { input: readFileSync(join(testDir, file)), stdio: ["pipe", "inherit", "inherit"] },
  );
  if (result.error) {
    console.error(`Could not run docker: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) failed = true;
}

process.exit(failed ? 1 : 0);
