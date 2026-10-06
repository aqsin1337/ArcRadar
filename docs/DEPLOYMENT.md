# Deploying ArcRadar

This guide takes you from nothing to a running ArcRadar of your own: a database on Supabase, the app on
Vercel, your first administrator, your team, and a SIEM sending alerts. It fits in the free plans of both
services. There is no server to keep running: the app is serverless, and all state lives in Postgres.

The short version of the same steps is the [Quick start in the README](../README.md#quick-start).

| Step                                                               | Where                  | Time   |
| ------------------------------------------------------------------ | ---------------------- | ------ |
| [1. Create the database](#1-create-the-database)                   | Supabase, your machine | 10 min |
| [2. Set the sign-in rules](#2-set-the-sign-in-rules)               | Supabase               | 3 min  |
| [3. Deploy the app](#3-deploy-the-app)                             | Vercel                 | 5 min  |
| [4. Make the first administrator](#4-make-the-first-administrator) | The app, Supabase      | 3 min  |
| [5. Add your team](#5-add-your-team)                               | The app                | 2 min  |
| [6. Load reference data](#6-load-reference-data)                   | The app, your machine  | 5 min  |
| [7. Add provider keys](#7-add-provider-keys)                       | The app                | 5 min  |
| [8. Connect a SIEM](#8-connect-a-siem)                             | Your SIEM host         | 15 min |

## What you need

- A [GitHub](https://github.com) account, with your own fork of this repository.
- A [Supabase](https://supabase.com) account and a [Vercel](https://vercel.com) account. The free plans
  are enough.
- On your own computer, once, to create the database: [git](https://git-scm.com) and
  [Node.js](https://nodejs.org) 20.19 or newer.

## 1. Create the database

1. In the Supabase dashboard, create a **new project**. Pick a region near you and set a database
   password (you will not need it again).
2. Open **Project Settings > API** and keep three values at hand:

   | Value               | Used as                         |
   | ------------------- | ------------------------------- |
   | Project URL         | `NEXT_PUBLIC_SUPABASE_URL`      |
   | `anon` `public` key | `NEXT_PUBLIC_SUPABASE_ANON_KEY` |
   | `service_role` key  | `SUPABASE_SERVICE_ROLE_KEY`     |

   The service-role key bypasses every permission check. It only ever goes into Vercel as a secret.

3. On your computer, get the code and send the schema to the project. The project reference is the
   part of the Project URL before `.supabase.co`.

   ```bash
   git clone https://github.com/<your-account>/ArcRadar.git
   cd ArcRadar
   npm install
   npx supabase login
   npx supabase link --project-ref <project-ref>
   npx supabase db push
   ```

   `db push` runs every file in `supabase/migrations/` in order. It creates the tables, the roles and
   permissions, the row-level security policies and the audit log. It does not load any demo data.

4. Check it: the **Table Editor** in the dashboard now lists the tables (`alerts`, `indicators`,
   `investigations`, `profiles` and so on).

## 2. Set the sign-in rules

A new Supabase project does not start with the settings ArcRadar expects. In the dashboard:

- **Authentication > URL Configuration**
  - **Site URL**: the address your app will have (`https://<project-name>.vercel.app`, or your own
    domain).
  - **Redirect URLs**: add `https://<that address>/**`. Password-reset links depend on it.
- **Authentication > Sign In / Providers > Email**
  - **Minimum password length**: `10`, and require **lowercase, uppercase and digits**. The app shows
    the same rules on its forms, so the two must agree.
  - **Confirm email**: your choice.
    - **On**: someone who signs up must click a link in a mail before they can sign in. Supabase's
      built-in mail sender only sends a few mails an hour, so set up your own SMTP server under
      **Authentication > Emails** if you expect more than a handful of sign-ups.
    - **Off**: no mail is needed. This is safe to choose: an account still cannot do anything until an
      administrator approves it (step 5), and that approval, not the mail, is what protects the
      workspace.

Accounts an administrator creates from inside the app (step 5) never need a confirmation mail, whichever
you choose.

## 3. Deploy the app

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Faqsin1337%2FArcRadar&env=NEXT_PUBLIC_SUPABASE_URL,NEXT_PUBLIC_SUPABASE_ANON_KEY,SUPABASE_SERVICE_ROLE_KEY,NEXT_PUBLIC_APP_URL,SECRETS_ENCRYPTION_KEY&envDescription=The%20three%20Supabase%20values%20from%20step%201%2C%20the%20address%20of%20this%20deployment%2C%20and%2032%20random%20bytes%20in%20base64.&envLink=https%3A%2F%2Fgithub.com%2Faqsin1337%2FArcRadar%2Fblob%2Fmain%2Fdocs%2FDEPLOYMENT.md%233-deploy-the-app&project-name=arcradar&repository-name=arcradar)

The button copies the repository into your GitHub account and asks for the settings below. If you
already forked it, use **Add New > Project** in Vercel and import your fork instead. Either way the
defaults are right: Next.js is detected, and no build settings need changing.

| Setting                         | Value                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `NEXT_PUBLIC_SUPABASE_URL`      | The Project URL from step 1                                                                               |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | The `anon` key from step 1                                                                                |
| `SUPABASE_SERVICE_ROLE_KEY`     | The `service_role` key from step 1. Mark it **Sensitive**                                                 |
| `NEXT_PUBLIC_APP_URL`           | The address of this deployment, the same one you set as Site URL in step 2                                |
| `SECRETS_ENCRYPTION_KEY`        | 32 random bytes in base64. Make one with `openssl rand -base64 32`. Mark it **Sensitive** and keep a copy |

No `openssl`? This prints the same thing:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

`SECRETS_ENCRYPTION_KEY` is what lets you paste provider keys inside the app later (step 7) instead of
editing Vercel settings. If you lose it, the saved keys cannot be read and must be pasted again.

Press **Deploy**. When it finishes, open `https://<your address>/api/health`. It should answer:

```json
{ "success": true, "data": { "app": "arcradar", "status": "ok", "supabase": "ok" }, "error": null }
```

If `supabase` is not `ok`, one of the Supabase values is wrong. Paste them again (typing them into
the Vercel dashboard by hand is where mistakes happen) and redeploy.

Every other setting is optional and is listed under [Configuration in the README](../README.md#configuration).

## 4. Make the first administrator

Nobody can sign up as an administrator, and a fresh workspace has no administrator to approve anyone.
So the first one is made by hand, once.

1. Open your app, choose **Request access** and sign up with your own email and a password. If you left
   **Confirm email** on, click the link in the mail.
2. In the Supabase dashboard, open the **SQL Editor** and run this with your email:

   ```sql
   update public.profiles
   set role_name = 'admin', is_active = true
   where id = (select id from auth.users where email = 'you@example.com');
   ```

   It should report one row updated. Prefer the command line? From the project folder,
   `npm run bootstrap:admin -- --email you@example.com --url <Project URL>` does the same, with
   `SUPABASE_SERVICE_ROLE_KEY` set in your shell for that one command.

3. Sign in. You are the administrator, and from now on everything is done inside the app.

## 5. Add your team

Open **Settings**. There are two ways for a teammate to get an account:

- **You add them.** Press **Add account**, enter their name, email, role and a first password, and pass
  the password on. The account works at once, and they can change the password on their **Profile**
  page.
- **They sign up.** They use **Request access** on the front page. Their account appears in Settings as
  **Pending approval**, and cannot do anything until you pick a role and press **Approve**.

| Role   | For                                                                                            |
| ------ | ---------------------------------------------------------------------------------------------- |
| Viewer | Reading alerts, cases, indicators, vulnerabilities and reports                                 |
| SOC L1 | Triage: acknowledge, assign and close alerts, ask the AI for an analysis                       |
| SOC L2 | Investigation: open cases, write indicators and reports, run live lookups                      |
| Admin  | Everything, including detection rules, integrations, provider keys, accounts and the audit log |

An administrator cannot change their own role or disable themselves, and the last active administrator
cannot be removed, so the workspace can never be locked out of itself.

## 6. Load reference data

A new workspace is empty on purpose: ArcRadar shows what happens on the machines it watches, not a
catalogue. Two things are still worth loading.

- **MITRE ATT&CK technique names.** The matrix page needs them to name the techniques your alerts
  mention. From the project folder on your computer:

  ```bash
  SUPABASE_SERVICE_ROLE_KEY=<service_role key> npm run import:mitre -- --url <Project URL>
  ```

  On Windows PowerShell, set the key first with `$env:SUPABASE_SERVICE_ROLE_KEY = "<service_role key>"`
  and then run the `npm` part. It downloads the official ATT&CK file (about 54 MB) and can be run again
  whenever MITRE publishes a new version.

- **Public threat feeds.** Open **Integrations** in the app and press **Import now**. It brings in
  abuse.ch indicators (URLhaus, Feodo Tracker, ThreatFox) and CISA's list of known exploited
  vulnerabilities. Nothing is imported on a schedule: it happens when you press the button.

## 7. Add provider keys

Everything here is optional. ArcRadar works with none of it, and each one you add switches on one more
thing. Open **API keys** in the app and scroll to **Keys ArcRadar uses**. Paste a key, press save, and it
is used at once. Keys are encrypted before they are stored and are never shown again.

| Key                               | Switches on                                                          | Where to get it                              |
| --------------------------------- | -------------------------------------------------------------------- | -------------------------------------------- |
| VirusTotal                        | Lookups of addresses, domains, URLs and file hashes                  | virustotal.com, free account                 |
| AbuseIPDB                         | Reputation of IP addresses                                           | abuseipdb.com, free account                  |
| AlienVault OTX                    | Community threat reports for an indicator                            | otx.alienvault.com, free account             |
| Shodan InternetDB                 | Open ports and known vulnerabilities of an address. A switch, no key | No account needed                            |
| NVD                               | Importing a CVE into the vulnerability list                          | nvd.nist.gov, free key                       |
| Groq, OpenAI, Anthropic, DeepSeek | AI analysis of alerts, cases and indicators, and AI rule drafts      | The provider's console. Groq has a free tier |
| GitHub token, repository, branch  | Sending detection rules to your rules repository                     | See [step 8](#8-connect-a-siem)              |

After adding an AI key, open **Integrations**, find **AI provider** and make that provider the active
one. Only one is active at a time.

The same keys can be set as Vercel environment variables instead (names in the
[README](../README.md#configuration)). A key saved in the app wins over the variable.

## 8. Connect a SIEM

ArcRadar never logs in to your SIEM. The SIEM sends its alerts to ArcRadar, and picks up detection rules
from a Git repository you own.

1. **Make an API key for the SIEM.** In the app, open **API keys**, press **New key**, give it a name
   such as "Wazuh Manager" and choose the scope for your SIEM. The key is shown once: copy it now.
2. **Install the sender on the SIEM host**, with your app's address and that key:
   - Wazuh: [`docs/WAZUH_INTEGRATION.md`](WAZUH_INTEGRATION.md)
   - Splunk: [`docs/SPLUNK_INTEGRATION.md`](SPLUNK_INTEGRATION.md)
3. **Check it.** Open **Telemetry** in the app. The card for your SIEM says **Receiving** once the first
   alert has arrived.

To also write detection rules in ArcRadar and have the SIEM load them:

1. Create a GitHub repository for the rules. It can be empty, and public or private.
2. Create a **fine-grained personal access token** on GitHub that can reach only that repository, with
   the permission **Contents: Read and write** and nothing else.
3. In the app, under **API keys > Keys ArcRadar uses**, save the token, the repository
   (`owner/name`) and the branch (`main`).
4. Install the apply script on the SIEM host. It pulls the repository, checks every file, tests it and
   only then loads it: [`docs/WAZUH_RULES.md`](WAZUH_RULES.md) for Wazuh,
   [`docs/SPLUNK_INTEGRATION.md`](SPLUNK_INTEGRATION.md) for Splunk.

## Check the deployment

- `/api/health` answers `"status": "ok"` and `"supabase": "ok"`.
- The response headers of any page carry a `Content-Security-Policy` with a `nonce-` and a
  `Strict-Transport-Security` header (your browser's developer tools show them, or `curl -I`).
- Signing in with a wrong password thirty times in five minutes from one address is answered with
  `429`. Rate limiting needs no setup: it uses a table that step 1 created.
- **Audit log** in the app shows your own sign-in and everything you changed.

## Updating to a newer version

```bash
git pull                 # in your copy of the repository
npx supabase db push     # applies any new database migrations
git push                 # Vercel builds and deploys the new version
```

Run `db push` before the new code goes live: the code may expect tables the old database does not have.

## Good to know

- **The free Supabase plan pauses a project** after about a week without traffic. The first request
  after that takes a minute. Opening `/api/health` wakes it.
- **Secrets stay on the server.** Only the two `NEXT_PUBLIC_SUPABASE_*` values and the app address reach
  the browser, and they are public by design: row-level security is what protects the data.
- **Do not set `NEXT_PUBLIC_DEMO_LOGINS`.** It shows one-click demo accounts that only exist in a local
  development database.
- **A local AI model (Ollama)** can be used by setting `OLLAMA_BASE_URL` in Vercel, but only if it runs
  somewhere your Vercel deployment can reach. An address on your own laptop is not.
- **Your own domain** is added in Vercel under **Settings > Domains**. Afterwards change
  `NEXT_PUBLIC_APP_URL` in Vercel and the Site URL and Redirect URLs in Supabase (step 2) to match, and
  redeploy.

## When something is wrong

| You see                                              | Cause and fix                                                                                                                 |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `/api/health` says `"supabase": "not_configured"`    | The Supabase URL or `anon` key is missing in Vercel. Add it and redeploy.                                                     |
| `/api/health` says `"supabase": "unreachable"`       | A Supabase value is wrong, or the project is paused. Paste the values again; open the Supabase dashboard to wake the project. |
| "Confirm your email address before signing in"       | **Confirm email** is on and the link was not clicked. Click it, or turn the setting off (step 2).                             |
| "Your account is waiting for an administrator"       | Working as designed. An administrator approves it in **Settings**.                                                            |
| The password is refused on sign-up but looks valid   | The password rules in Supabase differ from step 2. Set them to 10 characters with lowercase, uppercase and digits.            |
| The password-reset link opens an error page          | The Site URL or Redirect URLs in Supabase do not match the app's real address (step 2).                                       |
| A provider shows "not configured" after saving a key | `SECRETS_ENCRYPTION_KEY` is missing or changed in Vercel. Set it, redeploy, and save the key again.                           |
| The matrix page shows technique ids without names    | The ATT&CK catalogue was not loaded (step 6).                                                                                 |
