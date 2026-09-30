# Deploying ArcRadar (Vercel + Supabase)

This is a guide for **you** to follow with your own Vercel and Supabase accounts — Claude Code does not
deploy the app or sign in to either service (`CLAUDE.md`'s constraints). It has been checked against how
the app is built (env parsing, migrations, Auth settings, the local seed) but the steps themselves have not
been run against a real hosted project yet (decision 17 in `docs/ARCRADAR_PROGRESS.md`).

There is no always-on server, no local-filesystem persistence and no background worker anywhere in the
app (decision 1) — nothing here needs a bigger plan than Vercel Hobby and Supabase Free.

## What you need

- A [Vercel](https://vercel.com) account, with this repository pushed to GitHub (or GitLab/Bitbucket).
- A [Supabase](https://supabase.com) account.
- The Supabase CLI you already have as a dev dependency (`npx supabase`); you do not need to install it
  globally.
- Optional: a domain you own, if you want something other than the free `*.vercel.app` address.

## 1. Create the hosted Supabase project

1. In the Supabase dashboard, create a new project (any region close to you; note the **database
   password** you set — you will not need it again unless you connect a SQL client directly).
2. From the project's **Settings > API** page, copy the **Project URL**, the **anon / publishable key**
   and the **service_role / secret key**. Keep the service-role key private — it bypasses every
   permission check in the app (`src/lib/supabase/admin.ts`).
3. Link your local checkout to the new project and push the schema (this runs every file in
   `supabase/migrations/`, in order; it does **not** run `supabase/seed.sql`, which is local-only and
   would fail — it references `pg_temp` helpers that only exist inside `db reset`):
   ```bash
   npx supabase link --project-ref <project-ref>
   npx supabase db push
   ```
4. Confirm it worked: the Supabase dashboard's **Table Editor** should show the same tables `npm run
db:reset` gives you locally (40 tables as of Phase 11 — `select count(*) from pg_tables where
schemaname = 'public';` in the SQL editor if you want the exact number for the version you deployed).

## 2. Match the Auth settings

A hosted Supabase project's Auth defaults are not the same as `supabase/config.toml`'s local defaults.
In the dashboard, **Authentication > Providers > Email** and **Authentication > URL Configuration**:

- Password policy: minimum length **10**, requiring lowercase, uppercase and digits (mirrors
  `[auth]` in `supabase/config.toml`) — otherwise a client-side-valid sign-up can be rejected by the
  server in a confusing way, since `src/lib/validation/auth.ts`'s `PASSWORD_RULES` assumes this policy.
- **Site URL** and **Redirect URLs**: set to your deployed app's URL (the `*.vercel.app` address, or your
  domain once you add one), allowing `<your app url>/**`. This is what
  `POST /api/auth/forgot-password`'s recovery link and `GET /auth/callback` depend on.
- **Confirm email**: on (sign-up answers `201` either way — see "Auth behavior worth knowing" in
  `docs/API.md` — but a real deployment should require the click).
- **Allow new users to sign up**: turn this **off** once you have made your admin account (step 5), if
  the deployment is meant to be invite-only. A new sign-up is always a read-only `viewer` regardless
  (enforced by a database trigger, not by anything the client sends), so leaving it on is not a
  privilege-escalation risk, just an open door.

The full list, and why each one matters, is at the bottom of `docs/API.md`.

## 3. Deploy to Vercel

1. Import the GitHub repository as a new Vercel project. The defaults are correct: Next.js is
   auto-detected, the build command is `next build`, no `vercel.json` is needed.
2. In **Project Settings > Environment Variables**, add (see `.env.example` for what each one is):
   - `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` — from step 1.
   - `NEXT_PUBLIC_APP_URL` — the exact URL Vercel will serve this project at (its `*.vercel.app`
     address, or your domain). Auth redirects depend on this matching what you set in step 2.
   - `SUPABASE_SERVICE_ROLE_KEY` — from step 1. **Never** put this in a `NEXT_PUBLIC_*` variable.
   - `NEXT_PUBLIC_DEMO_LOGINS` — leave unset (or `false`). Setting it to `true` would show the
     one-click demo-account buttons on the sign-in page, and the local seed's demo accounts do not
     exist on a hosted project anyway.
   - `OTX_API_KEY` (free, otx.alienvault.com) and `SHODAN_INTERNETDB=true` (free, no key) switch on two
     more lookup providers; `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` two others.
   - `GITHUB_TOKEN`, `GITHUB_RULES_REPO`, `GITHUB_RULES_BRANCH` — only for the Detection rules page's
     "Send to GitHub" (a fine-grained token limited to the rules repository with Contents: Read and write;
     `docs/WAZUH_RULES.md`). Without them the page still drafts and reviews rules.
   - Any intel or AI provider keys you want live from day one (`VIRUSTOTAL_API_KEY`,
     `GROQ_API_KEY`, ...) — all optional; the app works with none of them set. `OLLAMA_BASE_URL`
     needs a server your Vercel deployment can actually reach over the network, which a laptop's
     `127.0.0.1` is not — leave it unset unless you host Ollama somewhere Vercel can reach.
3. Deploy. Vercel builds and serves the app; there is nothing else to configure (no `output` mode,
   no custom server) because the whole app is Route Handlers and Server Components already built for
   a serverless runtime — the same reason decision 1 rules out a background worker or in-memory state.

## 4. Make your first admin account

Every sign-up is a read-only `viewer` — the role is set by a database trigger, never read from the
request (decision 7) — so there is no way to sign up as an admin, and no admin exists yet to promote
anyone through the app itself (`PATCH /api/users/:id` needs an admin session).

1. Open the deployed app and sign up with your own email.
2. From your machine, with the hosted project's URL and **service-role key** (never commit either):
   ```bash
   SUPABASE_SERVICE_ROLE_KEY=<hosted service role key> \
   NEXT_PUBLIC_SUPABASE_URL=<hosted project URL> \
     npm run bootstrap:admin -- --email you@example.com
   ```
   This is the **one** place the service-role key is used outside the app itself: there is no admin
   session yet for `PATCH /api/users/:id` to check, so the script talks to the database directly
   (`scripts/bootstrap-admin.mjs`). It only ever changes the role of an account that already signed
   up; it cannot create one.
3. Sign in again (or refresh) — you now have the `admin` role and can promote or manage anyone else
   from **Settings**, the ordinary way, for good.

## 4b. Load the reference data

A hosted project starts empty. Two things fill it without any typing:

- **Threat feeds** are imported by an administrator pressing **Import now** on the Integrations page (abuse.ch indicators, CISA known-exploited vulnerabilities).
- **MITRE ATT&CK** (the technique catalog the matrix page lays out) is loaded once from your machine:
  ```bash
  SUPABASE_SERVICE_ROLE_KEY=<hosted service role key> \n    npm run import:mitre -- --url <hosted project URL>
  ```
  It downloads the official 54 MB STIX file and can be rerun any time to pick up a newer release.

## 5. Verify

- `<your app url>/api/health` answers `{"success":true,"data":{"app":"arcradar","status":"ok","supabase":"ok"},"error":null}`.
- Sign in, and check the response headers (browser DevTools, Network tab, or `curl -I`) carry a
  `Content-Security-Policy` with a `nonce-...` and `Strict-Transport-Security` (both are
  production-only — see decision 25 — so seeing them confirms `NODE_ENV=production`, which Vercel
  always sets).
- Rate limiting (`src/lib/rate-limit/`) needs no setup: it is backed by the `rate_limit_buckets` table
  you already pushed in step 1.
- If you plan to connect a real Wazuh Manager, it needs this deployment's public URL and an API key
  made the same way as locally (`docs/WAZUH_INTEGRATION.md`); the Manager pushes over HTTPS, so the
  free `*.vercel.app` certificate is enough.

## Things a hosted deployment is missing on purpose

- **No demo data.** `supabase/seed.sql` never runs on `supabase db push` (by design — it is local-only
  fixture data with a fictional scenario). A hosted project starts completely empty except for the
  reference data every migration inserts (permissions, role_permissions, the integration catalog,
  ATT&CK techniques where seeded — check which of those live in a migration versus `seed.sql` if you
  want a specific one on the hosted project too). If you want a demo to show people, create real
  `local` records by hand, or add a small, clearly-`demo`-labelled dataset of your own as a new
  migration (never edit an existing one).
- **No public landing page.** The bare app URL redirects a signed-out visitor straight to `/login`; the
  original spec's marketing pages (features, about, contact, docs) were deferred after Phase 7 and
  were never picked up in a later phase. A first-time visitor sees a sign-in form, not an explanation
  of what ArcRadar is.
- **The free Supabase tier pauses an inactive project** after about a week with no traffic. Visit the
  dashboard (or hit `/api/health`) before showing the deployment to anyone, or it needs a minute to wake
  up on the first request.
- **Nothing here has been run against a real hosted project yet.** Treat the first attempt as the trial
  deployment decision 17 always meant to be — expect to adjust something small, the same caveat every
  phase's live-service integration (VirusTotal, NVD, a real Wazuh Manager) has carried.
