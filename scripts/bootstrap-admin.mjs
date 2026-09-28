// Promotes an existing ArcRadar account to admin, directly against the database with the
// service-role key. This is the one legitimate reason to touch the database from outside the app
// entirely: a fresh deployment starts with no admin at all (every sign-up is a viewer, and role
// changes normally go through PATCH /api/users/:id, which itself needs an admin session) -- so
// there is no session this could piggy-back on. Sign up in the running app first; this script only
// changes that account's role, it never creates one.
//
//   SUPABASE_SERVICE_ROLE_KEY=... npm run bootstrap:admin -- --email you@example.com \
//       [--url https://<project-ref>.supabase.co]
//
// --url defaults to NEXT_PUBLIC_SUPABASE_URL (or SUPABASE_URL) from the environment; for the local
// stack that is already in .env.local (npm run db:env), but the service-role key is never read from
// a file automatically -- copy it from the Supabase dashboard (Project Settings > API) just for this
// one run, the same "never write a secret to disk twice" caution scripts/create-api-key.mjs's
// password already takes, and never commit it. Safe to run more than once: promoting an account
// that is already admin changes nothing.
import { createClient } from "@supabase/supabase-js";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};

function fail(message) {
  console.error(message);
  process.exitCode = 1; // not process.exit(): on Windows that can trip a libuv assertion with fetch timers pending
}

async function findUserByEmail(admin, email) {
  const target = email.trim().toLowerCase();
  for (let page = 1; page <= 10; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
    if (error) throw error;
    const match = data.users.find((user) => user.email?.toLowerCase() === target);
    if (match) return match;
    if (data.users.length < 200) break; // last page
  }
  return null;
}

async function main() {
  const email = option("email");
  if (!email) return fail("Usage: npm run bootstrap:admin -- --email you@example.com");

  const url = option("url") ?? process.env.NEXT_PUBLIC_SUPABASE_URL ?? process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url) return fail("Set NEXT_PUBLIC_SUPABASE_URL (or SUPABASE_URL), or pass --url.");
  if (!serviceKey) return fail("Set SUPABASE_SERVICE_ROLE_KEY first (Project Settings > API).");

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const user = await findUserByEmail(admin, email);
  if (!user) {
    return fail(`No account for ${email}. Sign up in the running app first, then rerun this.`);
  }

  const { data: profile, error: profileError } = await admin
    .from("profiles")
    .select("role_name, is_active")
    .eq("id", user.id)
    .maybeSingle();
  if (profileError) return fail(`Could not read the profile: ${profileError.message}`);
  if (!profile)
    return fail(`${email} has no profile row (an inconsistent account); investigate first.`);

  if (profile.role_name === "admin" && profile.is_active) {
    console.log(`${email} is already an active admin. Nothing to do.`);
    return;
  }

  const { error: updateError } = await admin
    .from("profiles")
    .update({ role_name: "admin", is_active: true })
    .eq("id", user.id);
  if (updateError) return fail(`Could not update the profile: ${updateError.message}`);

  console.log(`${email} is now an admin (and active, if it was not already).`);
}

main().catch((error) => fail(error instanceof Error ? error.message : String(error)));
